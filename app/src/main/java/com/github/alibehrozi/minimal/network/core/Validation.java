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

package com.github.alibehrozi.minimal.network.core;

import com.github.alibehrozi.minimal.network.NetworkException;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class Validation {

    public static final String NAME_SUBKEY_SERVERVALUE = ".sv";
    private static final Pattern INVALID_PATH_REGEX = Pattern.compile("[\\[\\]\\.#$]");
    private static final Pattern INVALID_KEY_REGEX =
            Pattern.compile("[\\[\\]\\.#\\$\\/\\u0000-\\u001F\\u007F]");

    private static boolean isValidPathString(String pathString) {
        return !INVALID_PATH_REGEX.matcher(pathString).find();
    }

    public static void validatePathString(String pathString) throws NetworkException {
        if (!isValidPathString(pathString)) {
            throw new NetworkException(
                    "Invalid Firebase Database path: "
                            + pathString
                            + ". Firebase Database paths must not contain '.', '#', '$', '[', or ']'");
        }
    }

    public static void validateRootPathString(String pathString) throws NetworkException {
        if (pathString.startsWith(".info")) {
            validatePathString(pathString.substring(5));
        } else if (pathString.startsWith("/.info")) {
            validatePathString(pathString.substring(6));
        } else {
            validatePathString(pathString);
        }
    }

    private static boolean isWritableKey(String key) {
        return key != null
                && key.length() > 0
                && (key.equals(".value")
                || key.equals(".priority")
                || (!key.startsWith(".") && !INVALID_KEY_REGEX.matcher(key).find()));
    }

    private static void validateDoubleValue(double d) {
        if (Double.isInfinite(d) || Double.isNaN(d)) {
            throw new NetworkException("Invalid value: Value cannot be NaN, Inf or -Inf.");
        }
    }

    @SuppressWarnings("unchecked")
    public static void validateWritableObject(Object object) {
        if (object instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) object;
            if (map.containsKey(NAME_SUBKEY_SERVERVALUE)) {
                // This will be short-circuited by conversion and we consider it valid
                return;
            }
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                validateWritableKey(entry.getKey());
                validateWritableObject(entry.getValue());
            }
        } else if (object instanceof List) {
            List<Object> list = (List<Object>) object;
            for (Object child : list) {
                validateWritableObject(child);
            }
        } else if (object instanceof Double || object instanceof Float) {
            validateDoubleValue((double) object);
        } else {
            // It's a primitive, should be fine
        }
    }

    public static void validateWritableKey(String key) throws NetworkException {
        if (!isWritableKey(key)) {
            throw new NetworkException(
                    "Invalid key: " + key + ". Keys must not contain '/', '.', '#', '$', '[', or ']'");
        }
    }
}