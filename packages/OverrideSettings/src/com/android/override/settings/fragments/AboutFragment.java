/*
 * Copyright (C) 2025 Android Override Project
 * Android 10 (API 29) version.
 */

package com.android.override.settings.fragments;

import android.app.Fragment;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;

import com.android.override.settings.R;

public class AboutFragment extends Fragment {

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_about, container, false);

        view.findViewById(R.id.link_github).setOnClickListener(v ->
                openUrl("https://github.com/ziachi"));
        view.findViewById(R.id.link_telegram).setOnClickListener(v ->
                openUrl("https://t.me/kalomakan"));
        view.findViewById(R.id.link_repo).setOnClickListener(v ->
                openUrl("https://github.com/ziachi/android-override-a10"));

        return view;
    }

    private void openUrl(String url) {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            startActivity(intent);
        } catch (ActivityNotFoundException e) {
            Toast.makeText(getActivity(), "No browser app installed", Toast.LENGTH_SHORT).show();
        }
    }
}
