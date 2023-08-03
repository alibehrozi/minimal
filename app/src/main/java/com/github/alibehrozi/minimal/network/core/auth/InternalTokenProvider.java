package com.github.alibehrozi.minimal.network.core.auth;

import com.github.alibehrozi.minimal.network.Task;
import com.github.alibehrozi.minimal.network.core.annotations.NotNull;
import com.github.alibehrozi.minimal.network.core.annotations.Nullable;

public interface InternalTokenProvider {
    @NotNull
    Task<GetTokenResult> getAccessToken(boolean var1);

    @Nullable
    String getUid();
}
