package com.github.alibehrozi.minimal.utilities.logging;

import android.util.Log;
import java.util.List;

public class AndroidLogger extends DefaultLogger {

    public AndroidLogger(Level level, List<String> enabledComponents) {
        super(level, enabledComponents);
    }

    @Override
    protected String buildLogMessage(Level level, String tag, String message, long msTimestamp) {
        // We'll log the level and tag separately on Android.
        return message;
    }

    @Override
    protected void error(String tag, String toLog) {
        Log.e(tag, toLog);
    }

    @Override
    protected void warn(String tag, String toLog) {
        Log.w(tag, toLog);
    }

    @Override
    protected void info(String tag, String toLog) {
        Log.i(tag, toLog);
    }

    @Override
    protected void debug(String tag, String toLog) {
        Log.d(tag, toLog);
    }
}