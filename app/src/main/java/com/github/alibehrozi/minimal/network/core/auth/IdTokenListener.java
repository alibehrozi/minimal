package com.github.alibehrozi.minimal.network.core.auth;


import com.github.alibehrozi.minimal.network.core.annotations.NotNull;

/**
 * Used to deliver notifications when authentication state changes.
 */
public interface IdTokenListener {

    /**
     * This method gets invoked on changes in the authentication state.
     * @param tokenResult represents the InternalTokenResult interface, which can be used to obtain a cached access token.
     */
    void onIdTokenChanged(@NotNull GetTokenResult tokenResult);
}