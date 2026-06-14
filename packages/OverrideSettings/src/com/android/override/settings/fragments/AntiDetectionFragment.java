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
import com.android.override.services.AntiDetection;
import com.android.override.settings.R;

import java.util.Map;

public class AntiDetectionFragment extends Fragment {

    private Switch mHideAppsSwitch;
    private LinearLayout mHiddenAppsList;
    private TextView mStatusInfo;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_anti_detection, container, false);

        OverrideController controller = OverrideController.getInstance();

        // Hide apps switch
        mHideAppsSwitch = view.findViewById(R.id.switch_hide_apps);
        mHideAppsSwitch.setChecked(controller.isHideAppsEnabled());
        mHideAppsSwitch.setOnCheckedChangeListener((btn, checked) -> {
            controller.setHideApps(checked);
        });

        // Hidden apps list
        mHiddenAppsList = view.findViewById(R.id.list_hidden_apps);
        view.findViewById(R.id.btn_add_hidden_app).setOnClickListener(v -> showAddHiddenAppDialog());

        // Status info
        mStatusInfo = view.findViewById(R.id.text_anti_detection_status);

        refreshHiddenApps();
        updateStatus();

        return view;
    }

    private void refreshHiddenApps() {
        mHiddenAppsList.removeAllViews();
        OverrideController controller = OverrideController.getInstance();
        Map<String, Boolean> hidden = controller.getHiddenApps();

        if (hidden.isEmpty()) {
            TextView empty = new TextView(getActivity());
            empty.setText("No custom hidden apps (built-in list always active)");
            empty.setPadding(16, 16, 16, 16);
            empty.setTextSize(13);
            mHiddenAppsList.addView(empty);
            return;
        }

        for (String pkg : hidden.keySet()) {
            TextView item = new TextView(getActivity());
            item.setText("• " + pkg);
            item.setPadding(16, 8, 16, 8);
            item.setTextSize(14);
            item.setOnLongClickListener(v -> {
                new AlertDialog.Builder(getActivity())
                        .setTitle("Unhide " + pkg + "?")
                        .setPositiveButton("Unhide", (d, w) -> {
                            controller.removeHiddenApp(pkg);
                            refreshHiddenApps();
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
                return true;
            });
            mHiddenAppsList.addView(item);
        }
    }

    private void showAddHiddenAppDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
        builder.setTitle("Add Hidden App");

        EditText input = new EditText(getActivity());
        input.setHint("com.example.app");
        builder.setView(input);

        builder.setPositiveButton("Add", (d, w) -> {
            String pkg = input.getText().toString().trim();
            if (!pkg.isEmpty()) {
                OverrideController.getInstance().addHiddenApp(pkg);
                refreshHiddenApps();
                Toast.makeText(getActivity(), "Hidden: " + pkg, Toast.LENGTH_SHORT).show();
            }
        });

        builder.setNegativeButton("Cancel", null);
        builder.show();
    }

    private void updateStatus() {
        mStatusInfo.setText(AntiDetection.getStatusInfo());
    }
}
