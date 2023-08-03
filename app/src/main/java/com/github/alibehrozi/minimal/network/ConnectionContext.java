package com.github.alibehrozi.minimal.network;

import com.github.alibehrozi.minimal.network.core.ConnectionTokenProvider;
import com.github.alibehrozi.minimal.utilities.logging.Logger;

import java.util.concurrent.ScheduledExecutorService;

public class ConnectionContext {
    private final ScheduledExecutorService executorService;
    private final ConnectionTokenProvider authTokenProvider;
    private final ConnectionTokenProvider appCheckTokenProvider;
    private final Logger logger;
    private final boolean persistenceEnabled;
    private final String clientSdkVersion;
    private final String userAgent;
    private final String applicationId;
    private final String sslCacheDirectory;

    public ConnectionContext(
            Logger logger,
            ConnectionTokenProvider authTokenProvider,
            ConnectionTokenProvider appCheckTokenProvider,
            ScheduledExecutorService executorService,
            boolean persistenceEnabled,
            String clientSdkVersion,
            String userAgent,
            String applicationId,
            String sslCacheDirectory) {
        this.logger = logger;
        this.authTokenProvider = authTokenProvider;
        this.appCheckTokenProvider = appCheckTokenProvider;
        this.executorService = executorService;
        this.persistenceEnabled = persistenceEnabled;
        this.clientSdkVersion = clientSdkVersion;
        this.userAgent = userAgent;
        this.applicationId = applicationId;
        this.sslCacheDirectory = sslCacheDirectory;
    }

    public Logger getLogger() {
        return this.logger;
    }

    public ConnectionTokenProvider getAuthTokenProvider() {
        return this.authTokenProvider;
    }

    public ConnectionTokenProvider getAppCheckTokenProvider() {
        return this.appCheckTokenProvider;
    }

    public ScheduledExecutorService getExecutorService() {
        return this.executorService;
    }

    public boolean isPersistenceEnabled() {
        return this.persistenceEnabled;
    }

    public String getClientSdkVersion() {
        return this.clientSdkVersion;
    }

    public String getUserAgent() {
        return this.userAgent;
    }

    public String getSslCacheDirectory() {
        return sslCacheDirectory;
    }

    public String getApplicationId() {
        return applicationId;
    }
}