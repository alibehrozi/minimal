package com.github.alibehrozi.minimal;

import android.app.Application;
import android.content.Context;

import com.github.alibehrozi.minimal.network.NetworkConnection;

import java.io.IOException;
import java.io.InputStream;

public class AppLoader extends Application {

    private static volatile Context applicationContext;

    public static InputStream getInputStreamFromAssets(String fileName) throws IOException {
        // Load file from assets folder
        return applicationContext.getAssets().open(fileName);
    }

    public static Context getContext() {
        return applicationContext;
    }

    @Override
    public void onCreate() {
        super.onCreate();

        if (applicationContext == null) {
            applicationContext = getApplicationContext();
        }

        NetworkConnection.getDefaultInstance();
    }
}
