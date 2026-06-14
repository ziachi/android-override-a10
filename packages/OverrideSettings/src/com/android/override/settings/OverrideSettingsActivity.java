/*
 * Copyright (C) 2025 Android Override Project
 * Android 10 (API 29) version.
 */

package com.android.override.settings;

import android.app.Activity;
import android.app.Fragment;
import android.app.FragmentTransaction;
import android.os.Bundle;
import android.util.Log;
import android.view.MenuItem;

import com.android.override.OverrideController;
import com.android.override.settings.fragments.MainFragment;

public class OverrideSettingsActivity extends Activity {

    private static final String TAG = "OVERRIDE_DEBUG";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.e(TAG, "=== OverrideSettingsActivity.onCreate() CALLED ===");

        try {
            OverrideController.init(this);
            Log.e(TAG, "=== OverrideController.init() SUCCEEDED ===");
        } catch (Throwable t) {
            Log.e(TAG, "=== OverrideController.init() FAILED ===", t);
        }

        setContentView(R.layout.activity_main);

        if (savedInstanceState == null) {
            getFragmentManager().beginTransaction()
                    .replace(R.id.fragment_container, new MainFragment())
                    .commit();
        }
    }

    public void switchFragment(Fragment fragment, String tag) {
        getFragmentManager().beginTransaction()
                .replace(R.id.fragment_container, fragment)
                .addToBackStack(tag)
                .setTransition(FragmentTransaction.TRANSIT_FRAGMENT_OPEN)
                .commit();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            onBackPressed();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onBackPressed() {
        if (getFragmentManager().getBackStackEntryCount() > 0) {
            getFragmentManager().popBackStack();
        } else {
            super.onBackPressed();
        }
    }
}
