package com.github.alibehrozi.minimal.network.core;

import android.annotation.SuppressLint;
import android.os.Handler;
import android.os.Looper;

public class AndroidEventTarget implements EventTarget {
    private final Handler handler;

    // TODO(b/258277572): Migrate to go/firebase-android-executors
    @SuppressLint("ThreadPoolCreation")
    public AndroidEventTarget() {
        this.handler = new Handler(Looper.getMainLooper());
    }

    @Override
    public void postEvent(Runnable r) {
        handler.post(r);
    }

    @Override
    public void shutdown() {
        // No-op on android, there's no thread to shutdown, this just posts to the main Looper
    }

    @Override
    public void restart() {
        // No-op
    }
}