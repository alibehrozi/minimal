package com.github.alibehrozi.minimal.network.core;


import com.github.alibehrozi.minimal.utilities.logging.Logger;

import java.io.File;
import java.util.List;

public interface Platform {
    Logger newLogger(Logger.Level level, List<String> components);

    EventTarget newEventTarget();

    RunLoop newRunLoop(Context ctx);

    String getUserAgent();

    String getPlatformVersion();

    File getSSLCacheDirectory();
}