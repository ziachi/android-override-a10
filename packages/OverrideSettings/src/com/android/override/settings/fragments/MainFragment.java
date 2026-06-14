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
import android.widget.TextView;

import com.android.override.OverrideController;
import com.android.override.settings.OverrideSettingsActivity;
import com.android.override.settings.R;

public class MainFragment extends Fragment {

    private TextView mStatusText;
    private TextView mFingerprintPreview;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_main, container, false);

        OverrideController controller = OverrideController.getInstance();

        // Status
        mStatusText = view.findViewById(R.id.text_status);
        mFingerprintPreview = view.findViewById(R.id.text_fingerprint_preview);

        // Navigation cards — GMS spoofing only
        view.findViewById(R.id.card_fingerprint).setOnClickListener(v ->
                navigateTo(new FingerprintFragment(), "fingerprint"));
        view.findViewById(R.id.card_keybox).setOnClickListener(v ->
                navigateTo(new KeyboxFragment(), "keybox"));
        view.findViewById(R.id.card_about).setOnClickListener(v ->
                navigateTo(new AboutFragment(), "about"));

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
        String fp = controller.getFingerprint();
        boolean hasKeybox = controller.isKeyboxEnabled();

        if (fp != null && !fp.isEmpty()) {
            String display = fp.length() > 50 ? fp.substring(0, 50) + "..." : fp;
            mFingerprintPreview.setText(display);
            mFingerprintPreview.setVisibility(View.VISIBLE);
            mStatusText.setText(hasKeybox ?
                    "Active — Spoofing with keybox" : "Active — Fingerprint set");
        } else {
            mFingerprintPreview.setVisibility(View.GONE);
            mStatusText.setText("Ready — Import fingerprint & keybox to activate");
        }
    }

    private void navigateTo(Fragment fragment, String tag) {
        ((OverrideSettingsActivity) getActivity()).switchFragment(fragment, tag);
    }
}
