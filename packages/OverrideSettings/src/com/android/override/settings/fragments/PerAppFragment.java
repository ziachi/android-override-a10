/*
 * Copyright (C) 2025 Android Override Project
 * Android 10 (API 29) version.
 */

package com.android.override.settings.fragments;

import android.app.AlertDialog;
import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import com.android.override.OverrideController;
import com.android.override.settings.R;

import java.util.Map;

public class PerAppFragment extends Fragment {

    private LinearLayout mAppList;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_per_app, container, false);

        mAppList = view.findViewById(R.id.list_per_app);

        view.findViewById(R.id.btn_add_app).setOnClickListener(v -> showAddAppDialog());

        refreshList();
        return view;
    }

    private void refreshList() {
        mAppList.removeAllViews();
        OverrideController controller = OverrideController.getInstance();
        Map<String, OverrideController.PerAppConfig> configs = controller.getAllPerAppConfigs();

        if (configs.isEmpty()) {
            TextView empty = new TextView(getActivity());
            empty.setText("No per-app configs. Tap + to add.");
            empty.setPadding(32, 32, 32, 32);
            mAppList.addView(empty);
            return;
        }

        for (Map.Entry<String, OverrideController.PerAppConfig> entry : configs.entrySet()) {
            View item = LayoutInflater.from(getActivity())
                    .inflate(R.layout.item_per_app, mAppList, false);

            OverrideController.PerAppConfig config = entry.getValue();

            TextView nameText = item.findViewById(R.id.text_app_name);
            TextView fpText = item.findViewById(R.id.text_app_fingerprint);
            Switch enableSwitch = item.findViewById(R.id.switch_app_enabled);

            nameText.setText(config.packageName);
            fpText.setText(config.fingerprint.isEmpty() ? "(uses global)" :
                    config.fingerprint.length() > 40 ?
                            config.fingerprint.substring(0, 40) + "..." : config.fingerprint);
            enableSwitch.setChecked(config.spoofingEnabled);

            enableSwitch.setOnCheckedChangeListener((btn, checked) -> {
                config.spoofingEnabled = checked;
                controller.setPerAppConfig(config);
            });

            item.setOnClickListener(v -> showEditDialog(config));

            item.setOnLongClickListener(v -> {
                new AlertDialog.Builder(getActivity())
                        .setTitle("Remove " + config.packageName + "?")
                        .setPositiveButton("Remove", (d, w) -> {
                            controller.removePerAppConfig(config.packageName);
                            refreshList();
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
                return true;
            });

            mAppList.addView(item);
        }
    }

    private void showAddAppDialog() {
        View dialogView = LayoutInflater.from(getActivity())
                .inflate(R.layout.dialog_per_app_config, null);

        EditText pkgEdit = dialogView.findViewById(R.id.edit_package_name);
        EditText fpEdit = dialogView.findViewById(R.id.edit_app_fingerprint);
        EditText modelEdit = dialogView.findViewById(R.id.edit_app_model);
        EditText mfrEdit = dialogView.findViewById(R.id.edit_app_manufacturer);
        EditText brandEdit = dialogView.findViewById(R.id.edit_app_brand);

        new AlertDialog.Builder(getActivity())
                .setTitle("Add Per-App Config")
                .setView(dialogView)
                .setPositiveButton("Add", (d, w) -> {
                    String pkg = pkgEdit.getText().toString().trim();
                    if (pkg.isEmpty()) {
                        Toast.makeText(getActivity(), "Package name required",
                                Toast.LENGTH_SHORT).show();
                        return;
                    }

                    OverrideController.PerAppConfig config =
                            new OverrideController.PerAppConfig(pkg);
                    config.fingerprint = fpEdit.getText().toString().trim();
                    config.model = modelEdit.getText().toString().trim();
                    config.manufacturer = mfrEdit.getText().toString().trim();
                    config.brand = brandEdit.getText().toString().trim();

                    OverrideController.getInstance().setPerAppConfig(config);
                    refreshList();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showEditDialog(OverrideController.PerAppConfig config) {
        View dialogView = LayoutInflater.from(getActivity())
                .inflate(R.layout.dialog_per_app_config, null);

        EditText pkgEdit = dialogView.findViewById(R.id.edit_package_name);
        EditText fpEdit = dialogView.findViewById(R.id.edit_app_fingerprint);
        EditText modelEdit = dialogView.findViewById(R.id.edit_app_model);
        EditText mfrEdit = dialogView.findViewById(R.id.edit_app_manufacturer);
        EditText brandEdit = dialogView.findViewById(R.id.edit_app_brand);

        pkgEdit.setText(config.packageName);
        pkgEdit.setEnabled(false);
        fpEdit.setText(config.fingerprint);
        modelEdit.setText(config.model);
        mfrEdit.setText(config.manufacturer);
        brandEdit.setText(config.brand);

        new AlertDialog.Builder(getActivity())
                .setTitle("Edit: " + config.packageName)
                .setView(dialogView)
                .setPositiveButton("Save", (d, w) -> {
                    config.fingerprint = fpEdit.getText().toString().trim();
                    config.model = modelEdit.getText().toString().trim();
                    config.manufacturer = mfrEdit.getText().toString().trim();
                    config.brand = brandEdit.getText().toString().trim();

                    OverrideController.getInstance().setPerAppConfig(config);
                    refreshList();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }
}
