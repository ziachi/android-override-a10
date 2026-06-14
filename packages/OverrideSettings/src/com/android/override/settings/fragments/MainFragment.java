/*
 * Copyright (C) 2025 Android Override Project
 * Android 10 (API 29) version.
 */

package com.android.override.settings.fragments;

import android.app.Fragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Switch;
import android.widget.TextView;

import com.android.override.OverrideController;
import com.android.override.settings.OverrideSettingsActivity;
import com.android.override.settings.R;

public class MainFragment extends Fragment {

    private Switch mMasterSwitch;
    private TextView mStatusText;
    private TextView mFingerprintPreview;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_main, container, false);

        OverrideController controller = OverrideController.getInstance();

        // Master switch
        mMasterSwitch = view.findViewById(R.id.switch_master);
        mMasterSwitch.setChecked(controller.isEnabled());
        mMasterSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            controller.setEnabled(isChecked);
            updateStatus();
        });

        // Status
        mStatusText = view.findViewById(R.id.text_status);
        mFingerprintPreview = view.findViewById(R.id.text_fingerprint_preview);

        // Navigation cards
        view.findViewById(R.id.card_fingerprint).setOnClickListener(v ->
                navigateTo(new FingerprintFragment(), "fingerprint"));
        view.findViewById(R.id.card_keybox).setOnClickListener(v ->
                navigateTo(new KeyboxFragment(), "keybox"));
        view.findViewById(R.id.card_per_app).setOnClickListener(v ->
                navigateTo(new PerAppFragment(), "per_app"));
        view.findViewById(R.id.card_profiles).setOnClickListener(v ->
                navigateTo(new ProfilesFragment(), "profiles"));
        view.findViewById(R.id.card_integrity).setOnClickListener(v ->
                navigateTo(new IntegrityFragment(), "integrity"));
        view.findViewById(R.id.card_anti_detection).setOnClickListener(v ->
                navigateTo(new AntiDetectionFragment(), "anti_detection"));

        updateStatus();
        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
        updateStatus();
    }

    private void updateStatus() {
        OverrideController controller = OverrideController.getInstance();

        if (controller.isEnabled()) {
            String fp = controller.getFingerprint();
            if (!fp.isEmpty()) {
                mStatusText.setText("Active — Override enabled");
                mFingerprintPreview.setText(fp.length() > 50 ?
                        fp.substring(0, 50) + "..." : fp);
                mFingerprintPreview.setVisibility(View.VISIBLE);
            } else {
                mStatusText.setText("Enabled — No fingerprint set");
                mFingerprintPreview.setVisibility(View.GONE);
            }
        } else {
            mStatusText.setText("Disabled — Device uses real identity");
            mFingerprintPreview.setVisibility(View.GONE);
        }
    }

    private void navigateTo(Fragment fragment, String tag) {
        ((OverrideSettingsActivity) getActivity()).switchFragment(fragment, tag);
    }
}
