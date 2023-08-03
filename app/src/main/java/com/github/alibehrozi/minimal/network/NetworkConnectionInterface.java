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

package com.github.alibehrozi.minimal.network;

import com.github.alibehrozi.minimal.network.core.annotations.Nullable;

import java.util.List;
import java.util.Map;

public interface NetworkConnectionInterface {

    abstract class Delegate {

        public void onDataUpdate(Object message, boolean isMerge, Long optTag) {
        }

        public void onConnect() {
        }

        public void onDisconnect() {
        }

        public void onConnectionStatus(boolean connectionOk) {
        }

        public void onServerInfoUpdate(Map<String, Object> updates) {
        }
    }

    // Auth

    void refreshAuthToken();

    void refreshAuthToken(String token);

    // AppCheck

    void refreshAppCheckToken();

    void refreshAppCheckToken(String token);

    // Listens

    void listen(Delegate listener);

    void unlisten(Delegate listener);

    // Writes

    void purgeOutstandingWrites();

    // Disconnects

    void onDisconnectMerge(
            List<String> path, Map<String, Object> updates, RequestResultCallback onComplete);

    void onDisconnectCancel(List<String> path, RequestResultCallback onComplete);

    Task<Void> sendValue(@Nullable Object value);

    void sendValue(@Nullable Object value, @Nullable NetworkConnection.CompletionListener listener);

    void goOnline();

    void goOffline();

}
