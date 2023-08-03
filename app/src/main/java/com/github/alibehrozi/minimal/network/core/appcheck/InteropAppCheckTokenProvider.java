// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.github.alibehrozi.minimal.network.core.appcheck;

import com.github.alibehrozi.minimal.network.Task;
import com.github.alibehrozi.minimal.network.core.annotations.NotNull;
import com.github.alibehrozi.minimal.network.core.appcheck.AppCheckTokenListener;
import com.github.alibehrozi.minimal.network.core.appcheck.AppCheckTokenResult;


/** @hide */
public interface InteropAppCheckTokenProvider {

    InteropAppCheckTokenProvider get();

    /**
     * Requests an {@link AppCheckTokenResult} from the installed {@code AppCheckFactory}. This will
     * always return a successful task, with an {@link AppCheckTokenResult} that contains either a
     * valid token, or a dummy token and an error string.
     */
    @NotNull
    Task<AppCheckTokenResult> getToken(boolean forceRefresh);

    /**
     * Requests an {@link AppCheckTokenResult} from the installed {@code AppCheckFactory}. This will
     * always return a successful task, with an {@link AppCheckTokenResult} that contains either a
     * valid token, or a dummy token and an error string. The token returned from this method will be
     * a one-time use token.
     */
    @NotNull
    Task<AppCheckTokenResult> getLimitedUseToken();

    /**
     * Registers a listener to changes in the token state. There can be more than one listener
     * registered at the same time for one or more FirebaseAppAuth instances. The listeners call back
     * on the UI thread whenever the current token associated with this FirebaseAppCheck changes.
     */
    void addAppCheckTokenListener(@NotNull AppCheckTokenListener listener);

    /** Unregisters a listener to changes in the token state. */
    void removeAppCheckTokenListener(@NotNull AppCheckTokenListener listener);
}