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

public class SocketMessage {
    private byte[] byteMessage;
    private String stringMessage;
    private final byte opcode;

    public SocketMessage(byte[] message) {
        this.byteMessage = message;
        this.opcode = Socket.OPCODE_BINARY;
    }

    public SocketMessage(String message) {
        this.stringMessage = message;
        this.opcode = Socket.OPCODE_TEXT;
    }

    public boolean isText() {
        return opcode == Socket.OPCODE_TEXT;
    }

    public boolean isBinary() {
        return opcode == Socket.OPCODE_BINARY;
    }

    public byte[] getBytes() {
        return byteMessage;
    }

    public String getText() {
        return stringMessage;
    }
}
