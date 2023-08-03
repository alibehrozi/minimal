package com.github.alibehrozi.minimal.network;

import com.github.alibehrozi.minimal.network.core.Deferred;
import com.github.alibehrozi.minimal.network.core.TokenProvider;
import com.github.alibehrozi.minimal.network.core.annotations.NotNull;
import com.github.alibehrozi.minimal.network.core.appcheck.AndroidAppCheckTokenProvider;
import com.github.alibehrozi.minimal.network.core.appcheck.InteropAppCheckTokenProvider;
import com.github.alibehrozi.minimal.network.core.auth.AndroidAuthTokenProvider;
import com.github.alibehrozi.minimal.network.core.auth.InternalAuthProvider;
import com.github.alibehrozi.minimal.utilities.logging.Logger;

public class NetworkConnectionComponent {

    /**
     * A map of RepoInfo to FirebaseDatabase instance.
     *
     * <p>TODO: This serves a duplicate purpose as RepoManager. We should clean up. TODO: We should
     * maybe be conscious of leaks and make this a weak map or similar but we have a lot of work to do
     * to allow FirebaseDatabase/Repo etc. to be GC'd.
     */

    private final TokenProvider authProvider;
    private final TokenProvider appCheckProvider;

    public NetworkConnectionComponent(
            Deferred<InternalAuthProvider> authProvider,
            Deferred<InteropAppCheckTokenProvider> appCheckProvider) {
        this.authProvider = new AndroidAuthTokenProvider(authProvider);
        this.appCheckProvider = new AndroidAppCheckTokenProvider(appCheckProvider);
    }

    /**
     * Provides instances of Firebase Database for the given RepoInfo
     */
    @NotNull
    synchronized NetworkConnection get(HostInfo info) {

        NetworkConfig defaultConfig = new NetworkConfig();
        defaultConfig.setLogLevel(Logger.Level.DEBUG);

        defaultConfig.setAuthTokenProvider(this.authProvider);
        defaultConfig.setAppCheckTokenProvider(this.appCheckProvider);

        defaultConfig.freeze();

        return new NetworkConnection(info, defaultConfig);
    }
}