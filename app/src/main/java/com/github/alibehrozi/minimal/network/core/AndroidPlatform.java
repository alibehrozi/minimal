package com.github.alibehrozi.minimal.network.core;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.os.Handler;

import com.github.alibehrozi.minimal.AppLoader;
import com.github.alibehrozi.minimal.utilities.logging.AndroidLogger;
import com.github.alibehrozi.minimal.utilities.logging.LogWrapper;
import com.github.alibehrozi.minimal.utilities.logging.Logger;

import java.io.File;
import java.util.List;

public class AndroidPlatform implements Platform {

    @Override
    public EventTarget newEventTarget() {
        return new AndroidEventTarget();
    }

    @Override
    public RunLoop newRunLoop(com.github.alibehrozi.minimal.network.core.Context ctx) {
        final LogWrapper logger = ctx.getLogger("RunLoop");
        return new DefaultRunLoop() {
            @Override
            public void handleException(final Throwable e) {
                final String message = DefaultRunLoop.messageForException(e);
                // First log with our logger
                logger.error(message, e);

                // Rethrow on main thread, so the application will crash
                // The exception might indicate that there is something seriously wrong and better crash,
                // than continue run in an undefined state...
                // TODO(b/258277572): Migrate to go/firebase-android-executors
                @SuppressLint("ThreadPoolCreation")
                Handler handler = new Handler(AppLoader.getContext().getMainLooper());
                handler.post(
                        () -> {
                            // throw new RuntimeException(message, e);
                        });

                // In a background process, the app may not actually crash. So we'll shutdown
                // the executor to avoid continuing to run in a corrupted state (and likely causing
                // other exceptions).
                getExecutorService().shutdownNow();
            }
        };
    }

    @Override
    public Logger newLogger(
            Logger.Level component,
            List<String> enabledComponents) {
        return new AndroidLogger(component, enabledComponents);
    }

    @Override
    public String getUserAgent() {
        return Build.VERSION.SDK_INT + "/Android";
    }

    @Override
    public String getPlatformVersion() {
        return "android-"; // + FirebaseDatabase.getSdkVersion();
    }

    @Override
    public File getSSLCacheDirectory() {
        // Note that this is the same folder that SSLSessionCache uses by default.
        return AppLoader.getContext().getDir("sslcache", Context.MODE_PRIVATE);
    }
}
