package com.github.alibehrozi.minimal.network.core;
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

import java.lang.Thread.UncaughtExceptionHandler;

public interface ThreadInitializer {

    ThreadInitializer defaultInstance =
            new ThreadInitializer() {
                @Override
                public void setName(Thread t, String name) {
                    t.setName(name);
                }

                @Override
                public void setDaemon(Thread t, boolean isDaemon) {
                    t.setDaemon(isDaemon);
                }

                @Override
                public void setUncaughtExceptionHandler(Thread t, UncaughtExceptionHandler handler) {
                    t.setUncaughtExceptionHandler(handler);
                }
            };

    void setName(Thread t, String name);

    void setDaemon(Thread t, boolean isDaemon);

    void setUncaughtExceptionHandler(Thread t, UncaughtExceptionHandler handler);
}
