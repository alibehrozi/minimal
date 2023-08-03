package com.github.alibehrozi.minimal.network.core.auth;

import com.github.alibehrozi.minimal.network.Task;
import com.github.alibehrozi.minimal.network.core.annotations.NotNull;
import com.github.alibehrozi.minimal.network.core.annotations.Nullable;

/**
 * Provides an interface for internal clients of Firebase Authentication to get
 * an access token for a signed-in user.
 */
public interface InternalAuthProvider extends InternalTokenProvider {

    /**
     * Fetches a valid STS Token.
     * @param forceRefresh force refreshes the token.
     *                     Should only be set to true if the token is invalidated out of band.
     * @return a Task
     */
    @NotNull
    Task<GetTokenResult> getAccessToken(boolean forceRefresh);

    /**
     * Returns a string used to uniquely identify a signed-in
     * user in a Firebase project's user database.
     * This identifier is opaque and does not correspond necessarily
     * to the user's email address or any other field.
     *
     * @return the string representation of the uid. Returns null if
     * FirebaseAuth is not added to the Firebase project,
     * or if there is not a currently signed-in user.
     */
    @Nullable
    String getUid();

    /**
     * Adds an {@link IdTokenListener IdTokenListener} to the list of interested listeners.
     * Also indicates that you need a fresh IdToken at all times,
     * turning on Proactive Token Refreshing. Unlike the public method,
     * this method does not trigger immediately when added.
     * @param listener represents the {@link IdTokenListener IdTokenListener} that should be
     *                 notified when the user state changes.
     */
    void addIdTokenListener(@NotNull IdTokenListener listener);

    /**
     * Removes an IdTokenListener from the list of interested listeners.
     * @param listenerToRemove Removes an {@link IdTokenListener IdTokenListener}
     *                         from the list of interested listeners.
     */
    void removeIdTokenListener(@NotNull IdTokenListener listenerToRemove);
}
