package com.github.alibehrozi.minimal;

import android.app.Application;
import android.content.Context;

import com.github.alibehrozi.minimal.network.NetworkConnection;

public class AppLoader extends Application {

    private static volatile Context applicationContext;

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
