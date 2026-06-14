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
import android.widget.TextView;
import android.widget.Toast;

import com.android.override.OverrideController;
import com.android.override.settings.R;

public class ProfilesFragment extends Fragment {

    private LinearLayout mProfileList;
    private TextView mActiveProfileText;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_profiles, container, false);

        mProfileList = view.findViewById(R.id.list_profiles);
        mActiveProfileText = view.findViewById(R.id.text_active_profile);

        view.findViewById(R.id.btn_save_profile).setOnClickListener(v -> showSaveDialog());

        refreshList();
        return view;
    }

    private void refreshList() {
        mProfileList.removeAllViews();
        OverrideController controller = OverrideController.getInstance();

        mActiveProfileText.setText("Active: " + controller.getActiveProfile());

        String[] profiles = controller.listProfiles();

        if (profiles.length == 0) {
            TextView empty = new TextView(getActivity());
            empty.setText("No saved profiles. Tap Save to create one.");
            empty.setPadding(32, 32, 32, 32);
            mProfileList.addView(empty);
            return;
        }

        for (String profile : profiles) {
            View item = LayoutInflater.from(getActivity())
                    .inflate(R.layout.item_profile, mProfileList, false);

            TextView nameText = item.findViewById(R.id.text_profile_name);
            boolean isActive = profile.equals(controller.getActiveProfile());
            nameText.setText(profile + (isActive ? " (active)" : ""));

            item.setOnClickListener(v -> {
                controller.loadProfile(profile);
                Toast.makeText(getActivity(), "Profile loaded: " + profile,
                        Toast.LENGTH_SHORT).show();
                refreshList();
            });

            item.setOnLongClickListener(v -> {
                new AlertDialog.Builder(getActivity())
                        .setTitle("Delete profile: " + profile + "?")
                        .setPositiveButton("Delete", (d, w) -> {
                            controller.deleteProfile(profile);
                            refreshList();
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
                return true;
            });

            mProfileList.addView(item);
        }
    }

    private void showSaveDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(getActivity());
        builder.setTitle("Save Profile");

        final EditText input = new EditText(getActivity());
        input.setHint("Profile name");
        builder.setView(input);

        builder.setPositiveButton("Save", (dialog, which) -> {
            String name = input.getText().toString().trim();
            if (name.isEmpty()) {
                Toast.makeText(getActivity(), "Name required", Toast.LENGTH_SHORT).show();
                return;
            }

            OverrideController.getInstance().saveProfile(name);
            Toast.makeText(getActivity(), "Profile saved: " + name,
                    Toast.LENGTH_SHORT).show();
            refreshList();
        });

        builder.setNegativeButton("Cancel", null);
        builder.show();
    }
}
