/*
 * Copyright (C) 2025 Android Override Project
 * Android 10 (API 29) version — SafetyNet checker.
 */

package com.android.override.settings.fragments;

import android.app.Fragment;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.android.override.services.IntegrityChecker;
import com.android.override.settings.R;

public class IntegrityFragment extends Fragment {

    private TextView mResultText;
    private ProgressBar mProgress;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_integrity, container, false);

        mResultText = view.findViewById(R.id.text_integrity_result);
        mProgress = view.findViewById(R.id.progress_integrity);

        view.findViewById(R.id.btn_run_check).setOnClickListener(v -> runCheck());

        return view;
    }

    private void runCheck() {
        mProgress.setVisibility(View.VISIBLE);
        mResultText.setText("Running SafetyNet diagnostics...");

        new AsyncTask<Void, Void, IntegrityChecker.SafetyNetDiagnostics>() {
            @Override
            protected IntegrityChecker.SafetyNetDiagnostics doInBackground(Void... voids) {
                return IntegrityChecker.runDiagnostics(getActivity());
            }

            @Override
            protected void onPostExecute(IntegrityChecker.SafetyNetDiagnostics result) {
                mProgress.setVisibility(View.GONE);
                if (result != null) {
                    mResultText.setText(result.getSummary());
                } else {
                    mResultText.setText("Diagnostics failed");
                }
            }
        }.execute();
    }
}
