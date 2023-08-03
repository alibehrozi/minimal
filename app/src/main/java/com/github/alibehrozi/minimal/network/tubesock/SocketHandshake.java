// Copyright 2018 Google LLC
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

package com.github.alibehrozi.minimal.network.tubesock;

import android.util.Base64;

import java.net.URI;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

class SocketHandshake {
    private final URI url;
    private final String protocol;
    private final String nonce;
    private final Map<String, String> extraHeaders;

    public SocketHandshake(URI url, String protocol, Map<String, String> extraHeaders) {
        this.url = url;
        this.protocol = protocol;
        this.extraHeaders = extraHeaders;
        this.nonce = this.createNonce();
    }


    public byte[] getHandshake() {
        String host = url.getHost();

        if (url.getPort() != -1) {
            host += ":" + url.getPort();
        }

        LinkedHashMap<String, String> header = new LinkedHashMap<String, String>();
        header.put("Host", host);
        header.put("Sec-Socket-Key", this.nonce);

        if (this.protocol != null) {
            header.put("Sec-WebSocket-Protocol", this.protocol);
        }

        if (this.extraHeaders != null) {
            for (String fieldName : this.extraHeaders.keySet()) {
                // Only checks for Field names with the exact same text,
                // but according to RFC 2616 (HTTP) field names are case-insensitive.
                if (!header.containsKey(fieldName)) {
                    header.put(fieldName, this.extraHeaders.get(fieldName));
                }
            }
        }

        String handshake = this.generateHeader(header);
        handshake += "\r\n";

        byte[] tmpHandShakeBytes = handshake.getBytes(Charset.defaultCharset());
        byte[] handshakeBytes = new byte[tmpHandShakeBytes.length];
        System.arraycopy(tmpHandShakeBytes, 0, handshakeBytes, 0, tmpHandShakeBytes.length);

        return handshakeBytes;
    }

    private String generateHeader(LinkedHashMap<String, String> headers) {
        StringBuilder header = new StringBuilder("");
        for (String fieldName : headers.keySet()) {
            header.append(fieldName).append(": ").append(headers.get(fieldName)).append("\r\n");
        }
        return header.toString();
    }

    private String createNonce() {
        byte[] nonce = new byte[16];
        for (int i = 0; i < 16; i++) {
            nonce[i] = (byte) rand(0, 255);
        }
        return Base64.encodeToString(nonce, Base64.NO_WRAP);
    }

    public void verifyServerStatusLine(String statusLine) {
        int statusCode = Integer.parseInt(statusLine.substring(statusLine.length() -3));

        switch (statusCode) {
            case 200:
                // Handshake successful, do nothing
                break;
            case 404:
                throw new SocketException("Connection failed: 404 Not Found");
            case 407:
                throw new SocketException("Connection failed: Proxy authentication not supported");
            default:
                throw new SocketException("Connection failed: Unknown status code " + statusCode);
        }
    }

    public void validateServerHandshakeHeaders(HashMap<String, String> lowercaseHeaders) {
        validateHeaderField(lowercaseHeaders, "Upgrade", "websocket");
        validateHeaderField(lowercaseHeaders, "Connection", "upgrade");
    }

    private void validateHeaderField(HashMap<String, String> lowercaseHeaders, String fieldName, String expectedValue) {
        String actualValue = lowercaseHeaders.get(fieldName.toLowerCase(Locale.US));
        if (!expectedValue.equalsIgnoreCase(actualValue)) {
            throw new SocketException("Connection failed: Missing or incorrect header field in server handshake: " + fieldName);
        }
    }

    private int rand(int min, int max) {
        int rand = (int) (Math.random() * max + min);
        return rand;
    }
}