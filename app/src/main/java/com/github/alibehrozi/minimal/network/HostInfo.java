package com.github.alibehrozi.minimal.network;


import java.net.URI;

public class HostInfo {

    private final String host;
    private final String namespace;
    private final boolean secure;

    public HostInfo(String host, String namespace, boolean secure) {
        this.host = host;
        this.namespace = namespace;
        this.secure = secure;
    }

    @Override
    public String toString() {
        return "http" + (secure ? "s" : "") + "://" + host;
    }

    public static URI getConnectionUrl(
            String host, boolean secure, String namespace, String optLastSessionId) {
        String scheme = secure ? "https" : "http";
        String url =
                scheme
                        + "://"
                        + host;
        return URI.create(url);
    }

    public String getHost() {
        return this.host;
    }

    public String getNamespace() {
        return this.namespace;
    }

    public boolean isSecure() {
        return secure;
    }
}
