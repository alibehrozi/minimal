package com.github.alibehrozi.minimal.network.core.auth;



import com.github.alibehrozi.minimal.network.core.annotations.NotNull;
import com.github.alibehrozi.minimal.network.core.annotations.Nullable;

import java.util.Map;

public class GetTokenResult {
    @Nullable
    private final String zza;
    private final Map<String, Object> zzb;

    public GetTokenResult(@Nullable String token, @NotNull Map<String, Object> claims) {
        this.zza = token;
        this.zzb = claims;
    }

    @Nullable
    public String getToken() {
        return this.zza;
    }

    public long getExpirationTimestamp() {
        return this.zza("exp");
    }

    public long getAuthTimestamp() {
        return this.zza("auth_time");
    }

    public long getIssuedAtTimestamp() {
        return this.zza("iat");
    }

    @Nullable
    public String getSignInProvider() {
        Map var1 = (Map)this.zzb.get("firebase");
        return var1 != null ? (String)var1.get("sign_in_provider") : null;
    }

    @Nullable
    public String getSignInSecondFactor() {
        Map var1 = (Map)this.zzb.get("firebase");
        return var1 != null ? (String)var1.get("sign_in_second_factor") : null;
    }

    @NotNull
    public Map<String, Object> getClaims() {
        return this.zzb;
    }

    private final long zza(String var1) {
        Integer var2 = (Integer)this.zzb.get(var1);
        return var2 == null ? 0L : var2.longValue();
    }
}
