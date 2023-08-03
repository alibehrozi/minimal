package com.github.alibehrozi.minimal.network.core;


import com.github.alibehrozi.minimal.network.ConnectionContext;
import com.github.alibehrozi.minimal.network.NetworkException;
import com.github.alibehrozi.minimal.utilities.logging.LogWrapper;
import com.github.alibehrozi.minimal.utilities.logging.Logger;

import java.io.File;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

public class Context {

    private static final long DEFAULT_CACHE_SIZE = 10 * 1024 * 1024;

    protected Logger logger;
    protected EventTarget eventTarget;
    protected TokenProvider authTokenProvider;
    protected TokenProvider appCheckTokenProvider;
    protected RunLoop runLoop;
    protected String persistenceKey;
    protected List<String> loggedComponents;
    protected String userAgent;
    protected Logger.Level logLevel = Logger.Level.DEBUG;
    protected boolean persistenceEnabled;
    protected long cacheSize = DEFAULT_CACHE_SIZE;
    private boolean frozen = false;
    private boolean stopped = false;

    private Platform platform;

    private Platform getPlatform() {
        if (platform == null) {
            initializeAndroidPlatform();
        }
        return platform;
    }

    private synchronized void initializeAndroidPlatform() {
        platform = new AndroidPlatform();
    }

    public boolean isFrozen() {
        return frozen;
    }

    public boolean isStopped() {
        return stopped;
    }

    public synchronized void freeze() {
        if (!frozen) {
            frozen = true;
            initServices();
        }
    }

    public void requireStarted() {
        if (stopped) {
            restartServices();
            stopped = false;
        }
    }

    private void initServices() {
        // Do the logger first, so that other components can get a LogWrapper
        ensureLogger();
        // Cache platform
        getPlatform();
        ensureUserAgent();
        // ensureStorage();
        ensureEventTarget();
        ensureRunLoop();
        ensureSessionIdentifier();
        ensureAuthTokenProvider();
        ensureAppTokenProvider();
    }

    private void restartServices() {
        eventTarget.restart();
        runLoop.restart();
    }

    void stop() {
        stopped = true;
        eventTarget.shutdown();
        runLoop.shutdown();
    }

    protected void assertUnfrozen() {
        if (isFrozen()) {
            throw new NetworkException(
                    "Modifications to DatabaseConfig objects must occur before they are in use");
        }
    }

    public List<String> getOptDebugLogComponents() {
        return this.loggedComponents;
    }

    public Logger.Level getLogLevel() {
        return this.logLevel;
    }

    public Logger getLogger() {
        return this.logger;
    }

    public LogWrapper getLogger(String component) {
        return new LogWrapper(logger, component);
    }

    public LogWrapper getLogger(String component, String prefix) {
        return new LogWrapper(logger, component, prefix);
    }

    public ConnectionContext getConnectionContext() {
        return new ConnectionContext(
                this.getLogger(),
                wrapTokenProvider(this.getAuthTokenProvider(), this.getExecutorService()),
                wrapTokenProvider(this.getAppCheckTokenProvider(), this.getExecutorService()),
                this.getExecutorService(),
                this.isPersistenceEnabled(),
                "1.0",
                this.getUserAgent(),
                "firebaseApp.getOptions().getApplicationId()",
                this.getSSLCacheDirectory().getAbsolutePath());
    }

    public boolean isPersistenceEnabled() {
        return this.persistenceEnabled;
    }

    public long getPersistenceCacheSizeBytes() {
        return this.cacheSize;
    }

    public EventTarget getEventTarget() {
        return eventTarget;
    }

    public RunLoop getRunLoop() {
        return runLoop;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getPlatformVersion() {
        return getPlatform().getPlatformVersion();
    }

    public String getSessionPersistenceKey() {
        return this.persistenceKey;
    }

    public TokenProvider getAuthTokenProvider() {
        return this.authTokenProvider;
    }

    public TokenProvider getAppCheckTokenProvider() {
        return this.appCheckTokenProvider;
    }

    private ScheduledExecutorService getExecutorService() {
        RunLoop loop = this.getRunLoop();
        if (!(loop instanceof DefaultRunLoop)) {
            // TODO: We really need to remove this option from the public DatabaseConfig
            // object
            throw new RuntimeException("Custom run loops are not supported!");
        }
        return ((DefaultRunLoop) loop).getExecutorService();
    }

    private void ensureLogger() {
        if (logger == null) {
            logger = getPlatform().newLogger(logLevel, loggedComponents);
        }
    }

    private void ensureRunLoop() {
        if (runLoop == null) {
            runLoop = platform.newRunLoop(this);
        }
    }

    private void ensureEventTarget() {
        if (eventTarget == null) {
            eventTarget = getPlatform().newEventTarget();
        }
    }

    private void ensureUserAgent() {
        if (userAgent == null) {
            userAgent = buildUserAgent(getPlatform().getUserAgent());
        }
    }

    private void ensureAuthTokenProvider() {
        Preconditions.checkNotNull(
                authTokenProvider, "You must register an authTokenProvider before initializing Context.");
    }

    private void ensureAppTokenProvider() {
        Preconditions.checkNotNull(
                appCheckTokenProvider,
                "You must register an appCheckTokenProvider before initializing Context.");
    }

    private void ensureSessionIdentifier() {
        if (persistenceKey == null) {
            persistenceKey = "default";
        }
    }

    private String buildUserAgent(String platformAgent) {
        String sb = "Firebase/" +
                "5" +
                "/" +
                "1.0" +
                "/" +
                platformAgent;
        return sb;
    }

    private static ConnectionTokenProvider wrapTokenProvider(
            final TokenProvider provider, ScheduledExecutorService executorService) {
        return (forceRefresh, callback) ->
                provider.getToken(
                        forceRefresh,
                        new TokenProvider.GetTokenCompletionListener() {
                            @Override
                            public void onSuccess(String token) {
                                executorService.execute(() -> callback.onSuccess(token));
                            }

                            @Override
                            public void onError(String error) {
                                executorService.execute(() -> callback.onError(error));
                            }
                        });
    }

    public File getSSLCacheDirectory() {
        return getPlatform().getSSLCacheDirectory();
    }
}