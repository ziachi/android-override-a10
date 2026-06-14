/*
 * Copyright (C) 2025 Android Override Project
 * Android 10 (API 29) version.
 */

package com.android.override.settings.fragments;

import android.app.AlertDialog;
import android.app.Fragment;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import com.android.override.KeyboxManager;
import com.android.override.OverrideController;
import com.android.override.settings.R;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class KeyboxFragment extends Fragment {

    private static final int PICK_KEYBOX_FILE = 1001;

    private Switch mKeyboxSwitch;
    private TextView mKeyboxStatus;
    private TextView mKeyboxAlgorithm;
    private TextView mKeyboxSlot;
    private TextView mKeyboxHealth;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_keybox, container, false);

        OverrideController controller = OverrideController.getInstance();

        mKeyboxSwitch = view.findViewById(R.id.switch_keybox);
        mKeyboxSwitch.setChecked(controller.isKeyboxEnabled());
        mKeyboxSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            controller.setKeyboxEnabled(isChecked);
            if (isChecked) {
                KeyboxManager.getInstance().load();
            }
            updateStatus();
        });

        mKeyboxStatus = view.findViewById(R.id.text_keybox_status);
        mKeyboxAlgorithm = view.findViewById(R.id.text_keybox_algorithm);
        mKeyboxSlot = view.findViewById(R.id.text_keybox_slot);
        mKeyboxHealth = view.findViewById(R.id.text_keybox_health);

        // Import from file picker — use */* to accept all file types
        view.findViewById(R.id.btn_import_keybox).setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
            intent.setType("*/*");
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            startActivityForResult(
                    Intent.createChooser(intent, "Select Keybox XML"), PICK_KEYBOX_FILE);
        });

        view.findViewById(R.id.btn_import_path).setOnClickListener(v ->
                showImportFromPathDialog());
        view.findViewById(R.id.btn_health_check).setOnClickListener(v ->
                checkHealth());
        view.findViewById(R.id.btn_manage_slots).setOnClickListener(v ->
                showSlotsDialog());

        updateStatus();
        return view;
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == PICK_KEYBOX_FILE && resultCode == getActivity().RESULT_OK
                && data != null && data.getData() != null) {
            importKeyboxFromUri(data.getData());
        }
    }

    private void importKeyboxFromUri(Uri uri) {
        try {
            InputStream is = getActivity().getContentResolver().openInputStream(uri);
            File tempFile = new File(getActivity().getCacheDir(), "keybox_import.xml");
            FileOutputStream fos = new FileOutputStream(tempFile);
            byte[] buf = new byte[8192];
            int len;
            while ((len = is.read(buf)) > 0) fos.write(buf, 0, len);
            is.close();
            fos.close();

            OverrideController controller = OverrideController.getInstance();
            boolean success = controller.importKeybox(tempFile.getAbsolutePath());

            if (success) {
                KeyboxManager.getInstance().reload();
                Toast.makeText(getActivity(), "Keybox imported!", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(getActivity(), "Invalid keybox format", Toast.LENGTH_LONG).show();
            }

            tempFile.delete();
            updateStatus();
        } catch (Exception e) {
            Toast.makeText(getActivity(),
                    "Error: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void showImportFromPathDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
        builder.setTitle("Import Keybox from Path");

        final EditText input = new EditText(getActivity());
        input.setHint("/sdcard/keybox.xml");
        builder.setView(input);

        builder.setPositiveButton("Import", (dialog, which) -> {
            String path = input.getText().toString().trim();
            if (!path.isEmpty()) {
                OverrideController controller = OverrideController.getInstance();
                boolean success = controller.importKeybox(path);
                if (success) {
                    KeyboxManager.getInstance().reload();
                    Toast.makeText(getActivity(), "Keybox imported!", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(getActivity(), "Import failed", Toast.LENGTH_LONG).show();
                }
                updateStatus();
            }
        });
        builder.setNegativeButton("Cancel", null);
        builder.show();
    }

    private void showSlotsDialog() {
        OverrideController controller = OverrideController.getInstance();
        String[] slots = controller.listKeyboxSlots();

        if (slots.length == 0) {
            Toast.makeText(getActivity(), "No keybox slots", Toast.LENGTH_SHORT).show();
            return;
        }

        String currentSlot = controller.getActiveKeyboxSlot();
        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
        builder.setTitle("Keybox Slots");

        String[] displaySlots = new String[slots.length];
        int checkedItem = 0;
        for (int i = 0; i < slots.length; i++) {
            displaySlots[i] = slots[i] + (slots[i].equals(currentSlot) ? " (active)" : "");
            if (slots[i].equals(currentSlot)) checkedItem = i;
        }

        final int[] selectedIndex = {checkedItem};
        builder.setSingleChoiceItems(displaySlots, checkedItem,
                (dialog, which) -> selectedIndex[0] = which);

        builder.setPositiveButton("Switch", (dialog, which) -> {
            controller.setActiveKeyboxSlot(slots[selectedIndex[0]]);
            KeyboxManager.getInstance().reload();
            Toast.makeText(getActivity(), "Switched to: " + slots[selectedIndex[0]],
                    Toast.LENGTH_SHORT).show();
            updateStatus();
        });
        builder.setNegativeButton("Cancel", null);
        builder.show();
    }

    private void checkHealth() {
        KeyboxManager keybox = KeyboxManager.getInstance();
        if (!keybox.isLoaded()) keybox.load();

        KeyboxManager.KeyboxHealth health = keybox.checkHealth();

        String statusText;
        switch (health.status) {
            case KeyboxManager.KeyboxHealth.STATUS_OK:
                statusText = "Healthy";
                break;
            case KeyboxManager.KeyboxHealth.STATUS_DEGRADED:
                statusText = "Degraded: " + health.message;
                break;
            case KeyboxManager.KeyboxHealth.STATUS_LIKELY_REVOKED:
                statusText = "Likely Revoked: " + health.message;
                break;
            default:
                statusText = "Not loaded";
                break;
        }

        mKeyboxHealth.setText(statusText);
        mKeyboxHealth.setVisibility(View.VISIBLE);
    }

    private void updateStatus() {
        OverrideController controller = OverrideController.getInstance();
        KeyboxManager keybox = KeyboxManager.getInstance();

        if (controller.isKeyboxEnabled() && keybox.isLoaded()) {
            mKeyboxStatus.setText("Loaded");
            mKeyboxAlgorithm.setText("Algorithm: " + keybox.getKeyAlgorithm());
            mKeyboxAlgorithm.setVisibility(View.VISIBLE);
            mKeyboxSlot.setText("Slot: " + controller.getActiveKeyboxSlot());
            mKeyboxSlot.setVisibility(View.VISIBLE);
        } else if (controller.isKeyboxEnabled()) {
            mKeyboxStatus.setText("Enabled but not loaded");
            mKeyboxAlgorithm.setVisibility(View.GONE);
            mKeyboxSlot.setVisibility(View.GONE);
        } else {
            mKeyboxStatus.setText("Disabled");
            mKeyboxAlgorithm.setVisibility(View.GONE);
            mKeyboxSlot.setVisibility(View.GONE);
        }
    }
}
