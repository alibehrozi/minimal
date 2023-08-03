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

import java.io.DataInputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;

/**
 * This class encapsulates the receiving and decoding of websocket frames. It is run from the thread
 * started by the websocket class. It does some best-effort error detection for violations of the
 * websocket spec.
 */
class SocketReceiver {
    private DataInputStream input = null;
    private Socket websocket = null;
    private SocketEventHandler eventHandler = null;
    private final byte[] inputHeader = new byte[112];
    private MessageBuilderFactory.Builder pendingBuilder;

    private volatile boolean stop = false;

    SocketReceiver(Socket websocket) {
        this.websocket = websocket;
    }

    void setInput(DataInputStream input) {
        this.input = input;
    }

    void run() {
        this.eventHandler = websocket.getEventHandler();
        while (!stop) {
            try {
                int offset = 0;
                offset += read(inputHeader, offset, 1);
                boolean fin = (inputHeader[0] & 0x80) != 0;
                boolean rsv = (inputHeader[0] & 0x70) != 0;
                if (rsv) {
                    throw new SocketException("Invalid frame received");
                } else {
                    byte opcode = (byte) (inputHeader[0] & 0xf);
                    offset += read(inputHeader, offset, 1);
                    byte length = inputHeader[1];
                    long payload_length = 0;
                    if (length < 126) {
                        payload_length = length;
                    } else if (length == 126) {
                        offset += read(inputHeader, offset, 2);
                        payload_length = ((long) (0xff & inputHeader[2]) << 8L) | (0xff & inputHeader[3]);
                    } else if (length == 127) {
                        // Does work up to MAX_VALUE of long (2^63-1) after that minus values are returned.
                        // However frames with such a high payload length are vastly unrealistic.
                        // TODO: add Limit for WebSocket Payload Length.
                        offset += read(inputHeader, offset, 8);
                        // Parse the bytes we just read
                        payload_length = parseLong(inputHeader, offset - 8);
                    }

                    byte[] payload = new byte[(int) payload_length];
                    read(payload, 0, (int) payload_length);
                    if (opcode == Socket.OPCODE_CLOSE) {
                        websocket.onCloseOpReceived();
                    } else if (opcode == Socket.OPCODE_PONG) {
                        // NOTE: as a client, we don't expect PONGs. No-op
                    } else if (opcode == Socket.OPCODE_TEXT
                            || opcode == Socket.OPCODE_BINARY
                            || opcode == Socket.OPCODE_PING
                            || opcode == Socket.OPCODE_NONE) {
                        // It's some form of application data. Decode the payload
                        appendBytes(fin, opcode, payload);
                    } else {
                        // Unsupported opcode
                        throw new SocketException("Unsupported opcode: " + opcode);
                    }
                }
            } catch (SocketTimeoutException sto) {
                continue;
            } catch (IOException ioe) {
                handleError(new SocketException("IO Error", ioe));
            } catch (SocketException e) {
                handleError(e);
            }
        }
    }

    private void appendBytes(boolean fin, byte opcode, byte[] data) {
        // A ping can show up in the middle of another fragmented message
        if (opcode == Socket.OPCODE_PING) {
            if (fin) {
                handlePing(data);
            } else {
                throw new SocketException("PING must not fragment across frames");
            }
        } else {
            if (pendingBuilder != null && opcode != Socket.OPCODE_NONE) {
                throw new SocketException("Failed to continue outstanding frame");
            } else if (pendingBuilder == null && opcode == Socket.OPCODE_NONE) {
                // Trying to continue something, but there's nothing to continue
                throw new SocketException("Received continuing frame, but there's nothing to continue");
            } else {
                if (pendingBuilder == null) {
                    // We aren't continuing another message
                    pendingBuilder = MessageBuilderFactory.builder(opcode);
                }
                if (!pendingBuilder.appendBytes(data)) {
                    throw new SocketException("Failed to decode frame");
                } else if (fin) {
                    SocketMessage message = pendingBuilder.toMessage();
                    pendingBuilder = null;
                    // The message assembly could still fail
                    if (message == null) {
                        throw new SocketException("Failed to decode whole message");
                    } else {
                        eventHandler.onMessage(message);
                    }
                }
            }
        }
    }

    private void handlePing(byte[] payload) {
        if (payload.length <= 125) {
            websocket.pong(payload);
        } else {
            throw new SocketException("PING frame too long");
        }
    }

    private long parseLong(byte[] buffer, int offset) {
        // Copied from DataInputStream#readLong
        return (((long) buffer[offset] << 56)
                + ((long) (buffer[offset + 1] & 255) << 48)
                + ((long) (buffer[offset + 2] & 255) << 40)
                + ((long) (buffer[offset + 3] & 255) << 32)
                + ((long) (buffer[offset + 4] & 255) << 24)
                + ((buffer[offset + 5] & 255) << 16)
                + ((buffer[offset + 6] & 255) << 8)
                + ((buffer[offset + 7] & 255) << 0));
    }

    private int read(byte[] buffer, int offset, int length) throws IOException {
        input.readFully(buffer, offset, length);
        return length;
    }

    void stopit() {
        stop = true;
    }

    boolean isRunning() {
        return !stop;
    }

    private void handleError(SocketException e) {
        stopit();
        websocket.handleReceiverError(e);
    }
}