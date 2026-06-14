/*
 * Copyright (C) 2025 Android Override Project
 * Android 10 (API 29) version.
 */

package com.android.override.settings.fragments;

import android.app.Fragment;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;

import com.android.override.OverrideController;
import com.android.override.settings.R;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Map;

public class FingerprintFragment extends Fragment {

    private static final int PICK_JSON_FILE = 2001;

    private EditText mFingerprintEdit;
    private EditText mModelEdit;
    private EditText mManufacturerEdit;
    private EditText mProductEdit;
    private EditText mDeviceEdit;
    private EditText mBrandEdit;
    private EditText mSecurityPatchEdit;
    private Spinner mDatabaseSpinner;
    private boolean mIgnoreSpinner = false;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_fingerprint, container, false);

        OverrideController controller = OverrideController.getInstance();

        mFingerprintEdit = view.findViewById(R.id.edit_fingerprint);
        mModelEdit = view.findViewById(R.id.edit_model);
        mManufacturerEdit = view.findViewById(R.id.edit_manufacturer);
        mProductEdit = view.findViewById(R.id.edit_product);
        mDeviceEdit = view.findViewById(R.id.edit_device);
        mBrandEdit = view.findViewById(R.id.edit_brand);
        mSecurityPatchEdit = view.findViewById(R.id.edit_security_patch);
        mDatabaseSpinner = view.findViewById(R.id.spinner_database);

        mFingerprintEdit.setText(controller.getFingerprint());
        mModelEdit.setText(controller.getModel());
        mManufacturerEdit.setText(controller.getManufacturer());
        mProductEdit.setText(controller.getProduct());
        mDeviceEdit.setText(controller.getDevice());
        mBrandEdit.setText(controller.getBrand());
        mSecurityPatchEdit.setText(controller.getSecurityPatch());

        setupDatabaseSpinner(controller);

        view.findViewById(R.id.btn_import_json).setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(
                    Intent.createChooser(intent, "Select Build JSON"), PICK_JSON_FILE);
        });

        view.findViewById(R.id.btn_save).setOnClickListener(v -> {
            controller.setFingerprint(mFingerprintEdit.getText().toString().trim());
            controller.setModel(mModelEdit.getText().toString().trim());
            controller.setManufacturer(mManufacturerEdit.getText().toString().trim());
            controller.setProduct(mProductEdit.getText().toString().trim());
            controller.setDevice(mDeviceEdit.getText().toString().trim());
            controller.setBrand(mBrandEdit.getText().toString().trim());
            controller.setSecurityPatch(mSecurityPatchEdit.getText().toString().trim());
            Toast.makeText(getActivity(), "Saved", Toast.LENGTH_SHORT).show();
        });

        view.findViewById(R.id.btn_clear).setOnClickListener(v -> {
            mFingerprintEdit.setText("");
            mModelEdit.setText("");
            mManufacturerEdit.setText("");
            mProductEdit.setText("");
            mDeviceEdit.setText("");
            mBrandEdit.setText("");
            mSecurityPatchEdit.setText("");
            controller.clearFingerprint();
            Toast.makeText(getActivity(), "Cleared", Toast.LENGTH_SHORT).show();
        });

        return view;
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_JSON_FILE && resultCode == getActivity().RESULT_OK
                && data != null && data.getData() != null) {
            importBuildJson(data.getData());
        }
    }

    private void importBuildJson(Uri uri) {
        try {
            InputStream is = getActivity().getContentResolver().openInputStream(uri);
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
            reader.close();
            is.close();

            JSONObject json = new JSONObject(sb.toString());

            if (json.has("FINGERPRINT") && !json.optString("FINGERPRINT").isEmpty()) {
                mFingerprintEdit.setText(json.getString("FINGERPRINT"));
            } else if (json.has("BRAND") && json.has("PRODUCT") && json.has("DEVICE")) {
                String fp = json.optString("BRAND", "") + "/"
                        + json.optString("PRODUCT", "") + "/"
                        + json.optString("DEVICE", "") + ":"
                        + json.optString("RELEASE", "10") + "/"
                        + json.optString("ID", "") + "/"
                        + json.optString("ID", "") + ":"
                        + json.optString("TYPE", "user") + "/release-keys";
                mFingerprintEdit.setText(fp);
            }

            if (json.has("MODEL")) mModelEdit.setText(json.getString("MODEL"));
            if (json.has("MANUFACTURER")) mManufacturerEdit.setText(json.getString("MANUFACTURER"));
            if (json.has("PRODUCT")) mProductEdit.setText(json.getString("PRODUCT"));
            if (json.has("DEVICE")) mDeviceEdit.setText(json.getString("DEVICE"));
            if (json.has("BRAND")) mBrandEdit.setText(json.getString("BRAND"));
            if (json.has("SECURITY_PATCH")) mSecurityPatchEdit.setText(json.getString("SECURITY_PATCH"));

            Toast.makeText(getActivity(),
                    "Imported: " + json.optString("MODEL", "Unknown"),
                    Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(getActivity(),
                    "Import failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void setupDatabaseSpinner(OverrideController controller) {
        Map<String, OverrideController.PropsEntry> db = controller.getPropsDatabase();
        ArrayList<String> labels = new ArrayList<>();
        labels.add("Select device...");
        labels.addAll(db.keySet());

        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                getActivity(), android.R.layout.simple_spinner_item, labels);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        mDatabaseSpinner.setAdapter(adapter);

        mDatabaseSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View v, int position, long id) {
                if (mIgnoreSpinner || position == 0) {
                    mIgnoreSpinner = false;
                    return;
                }
                String label = labels.get(position);
                OverrideController.PropsEntry entry = db.get(label);
                if (entry != null) {
                    mFingerprintEdit.setText(entry.fingerprint);
                    mModelEdit.setText(entry.model);
                    mManufacturerEdit.setText(entry.manufacturer);
                    mProductEdit.setText(entry.product);
                    mDeviceEdit.setText(entry.device);
                    mBrandEdit.setText(entry.brand);
                    mSecurityPatchEdit.setText(entry.securityPatch);
                    Toast.makeText(getActivity(), "Loaded: " + label,
                            Toast.LENGTH_SHORT).show();
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });
    }
}
