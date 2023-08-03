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

/**
 * This error is thrown when the Network Connection is unable to operate on the input it has
 * been given.
 */
public class NetworkException extends RuntimeException {

    /**
     * <strong>For internal use</strong>
     *
     * @hide
     * @param message A human readable description of the error
     */
    public NetworkException(String message) {
        super(message);
    }

    /**
     * <strong>For internal use</strong>
     *
     * @hide
     * @param message A human readable description of the error
     * @param cause The underlying cause for this error
     */
    public NetworkException(String message, Throwable cause) {
        super(message, cause);
    }
}