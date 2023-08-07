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

import android.os.Build;

import com.github.alibehrozi.minimal.network.ConnectionContext;
import com.github.alibehrozi.minimal.network.certificate.CertificateException;
import com.github.alibehrozi.minimal.network.certificate.CertificateUtils;
import com.github.alibehrozi.minimal.network.core.annotations.Nullable;
import com.github.alibehrozi.minimal.utilities.logging.LogWrapper;

import org.bouncycastle.operator.OperatorCreationException;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * This is the main class used to create a Socket connection. Create a new instance, set an event
 * handler, and then call connect(). Once the event handler's onOpen method has been called, call
 * send() on the Socket to transmit data.
 */
public class Socket {
    private static final int SSL_HANDSHAKE_TIMEOUT_MS = 60 * 1000;
    private static final String THREAD_BASE_NAME = "TubeSock";
    private static final AtomicInteger clientCount = new AtomicInteger(0);

    private enum State {
        NONE,
        CONNECTING,
        CONNECTED,
        DISCONNECTING,
        DISCONNECTED
    }

    private static final Charset UTF8 = StandardCharsets.UTF_8;

    static final byte OPCODE_NONE = 0x0;
    static final byte OPCODE_TEXT = 0x1;
    static final byte OPCODE_BINARY = 0x2;
    static final byte OPCODE_CLOSE = 0x8;
    static final byte OPCODE_PING = 0x9;
    static final byte OPCODE_PONG = 0xA;

    private volatile State state = State.NONE;
    private volatile java.net.Socket socket = null;

    private SocketEventHandler eventHandler = null;

    private final URI url;
    @Nullable
    private final String sslCacheDirectory;

    private final SocketReceiver receiver;
    private final SocketWriter writer;
    private final SocketHandshake handshake;
    private final LogWrapper logger;
    private final int clientId = clientCount.incrementAndGet();

    private final Thread innerThread;
    private static ThreadFactory threadFactory = Executors.defaultThreadFactory();
    private static ThreadInitializer intializer = Thread::setName;

    static ThreadFactory getThreadFactory() {
        return threadFactory;
    }

    static ThreadInitializer getIntializer() {
        return intializer;
    }

    public static void setThreadFactory(ThreadFactory threadFactory, ThreadInitializer intializer) {
        Socket.threadFactory = threadFactory;
        Socket.intializer = intializer;
    }

    /**
     * Create a Socket to connect to a given server
     *
     * @param url The URL of a Socket server
     */
    public Socket(ConnectionContext context, URI url) {
        this(context, url, null);
    }

    /**
     * Create a Socket to connect to a given server. Include protocol in Socket handshake
     *
     * @param url      The URL of a Socket server
     * @param protocol The protocol to include in the handshake. If null, it will be omitted
     */
    public Socket(ConnectionContext context, URI url, String protocol) {
        this(context, url, protocol, null);
    }

    /**
     * Create a Socket to connect to a given server. Include the given protocol in the handshake,
     * as well as any extra HTTP headers specified. Useful if you would like to include a User-Agent
     * or other header
     *
     * @param url          The URL of a Socket server
     * @param protocol     The protocol to include in the handshake. If null, it will be omitted
     * @param extraHeaders Any extra HTTP headers to be included with the initial request. Pass null
     *                     if not extra headers are requested
     */
    public Socket(
            ConnectionContext context, URI url, String protocol, Map<String, String> extraHeaders) {
        innerThread = getThreadFactory().newThread(this::runReader);
        this.url = url;
        sslCacheDirectory = context.getSslCacheDirectory();
        logger = new LogWrapper(context.getLogger(), "Socket", "sk_" + clientId);
        handshake = new SocketHandshake(url, protocol, extraHeaders);
        receiver = new SocketReceiver(this);
        writer = new SocketWriter(this, THREAD_BASE_NAME, clientId);
    }

    /**
     * Must be called before connect(). Set the handler for all Socket-related events.
     *
     * @param eventHandler The handler to be triggered with relevant events
     */
    public void setEventHandler(SocketEventHandler eventHandler) {
        this.eventHandler = eventHandler;
    }

    SocketEventHandler getEventHandler() {
        return this.eventHandler;
    }

    /**
     * Start up the socket. This is non-blocking, it will fire up the threads used by the library and
     * then trigger the onOpen handler once the connection is established.
     */
    public synchronized void connect() {
        if (state != State.NONE) {
            eventHandler.onError(new SocketException("connect() already called"));
            close();
            return;
        }
        getIntializer().setName(getInnerThread(), THREAD_BASE_NAME + "Reader-" + clientId);
        state = State.CONNECTING;
        getInnerThread().start();
    }

    /**
     * Send a TEXT message over the socket
     *
     * @param data The text payload to be sent
     */
    public synchronized void send(String data) {
        send(OPCODE_TEXT, data.getBytes(UTF8));
    }

    /**
     * Send a BINARY message over the socket
     *
     * @param data The binary payload to be sent
     */
    public synchronized void send(byte[] data) {
        send(OPCODE_BINARY, data);
    }

    synchronized void pong(byte[] data) {
        send(OPCODE_PONG, data);
    }

    private synchronized void send(byte opcode, byte[] data) {
        if (state != State.CONNECTED) {
            // We might have been disconnected on another thread, just report an error
            eventHandler.onError(new SocketException("error while sending data: not connected"));
        } else {
            try {
                writer.send(opcode, true, data);
            } catch (IOException e) {
                eventHandler.onError(new SocketException("Failed to send frame", e));
                close();
            }
        }
    }

    void handleReceiverError(SocketException e) {
        eventHandler.onError(e);
        if (state == State.CONNECTED) {
            close();
        }
        closeSocket();
    }

    /**
     * Close down the socket. Will trigger the onClose handler if the socket has not been previously
     * closed.
     */
    public synchronized void close() {
        switch (state) {
            case NONE:
                state = State.DISCONNECTED;
                return;
            case CONNECTING:
                // don't wait for an established connection, just close the tcp socket
                closeSocket();
                return;
            case CONNECTED:
                // This method also shuts down the writer
                // the socket will be closed once the ack for the close was received
                sendCloseHandshake();
                return;
            case DISCONNECTING:
                return; // no-op;
            case DISCONNECTED:
                // No-op
        }
    }

    void onCloseOpReceived() {
        closeSocket();
    }

    private synchronized void closeSocket() {
        if (state == State.DISCONNECTED) {
            return;
        }
        receiver.stopit();
        writer.stopIt();
        if (socket != null) {
            try {
                socket.close();
            } catch (Exception e) {
                eventHandler.onError(new SocketException("Failed to close", e));
            }
        }
        state = State.DISCONNECTED;

        eventHandler.onClose();
    }

    private void sendCloseHandshake() {
        try {
            state = State.DISCONNECTING;
            // Set the stop flag then queue up a message. This ensures that the writer thread
            // will wake up, and since we set the stop flag, it will exit its run loop.
            writer.stopIt();
            writer.send(OPCODE_CLOSE, true, new byte[0]);
        } catch (IOException e) {
            eventHandler.onError(new SocketException("Failed to send close frame", e));
        }
    }

    private java.net.Socket createSocket() {
        String scheme = url.getScheme();
        String host = url.getHost();
        int port = url.getPort();

        java.net.Socket socket;

        if (scheme != null && scheme.equals("http")) {
            if (port == -1) {
                port = 80;
            }
            try {
                socket = new java.net.Socket(host, port);
            } catch (UnknownHostException uhe) {
                throw new SocketException("unknown host: " + host, uhe);
            } catch (IOException ioe) {
                throw new SocketException("error while creating socket to " + url, ioe);
            }
        } else if (scheme != null && scheme.equals("https")) {
            if (port == -1) {
                port = 443;
            }

            // Create an instance of the CertificateUtils class, which is a utility class
            // responsible for creating and managing certificates
            CertificateUtils certificateUtils = new CertificateUtils();

            KeyManagerFactory keyManagerFactory;
            try {
                // Use the CertificateUtils to create a KeyManagerFactory.
                // The KeyManagerFactory is responsible for managing the client-side keys used during SSL/TLS handshake.
                keyManagerFactory = certificateUtils.initKeyManager(null);

            } catch (UnrecoverableKeyException uke) {
                throw new CertificateException("error while creating KeyManagerFactory", uke);
            } catch (java.security.cert.CertificateException ce) {
                throw new CertificateException("error while creating Certificate", ce);
            } catch (IOException ioe) {
                throw new CertificateException("io error with the client-certificate file.", ioe);
            } catch (NoSuchAlgorithmException nsae) {
                throw new CertificateException("Unknown algorithm: X.509 || RSA", nsae);
            } catch (KeyStoreException kse) {
                throw new CertificateException("error while initializing KeyStore with client-certificates", kse);
            } catch (GeneralSecurityException gse) {
                throw new CertificateException("security error while initializing client certificates", gse);
            } catch (OperatorCreationException oce) {
                throw new CertificateException("error while initializing client certificates", oce);
            }

            TrustManager[] allTrustManagers;
            TrustManagerFactory trustManagerFactory;
            TrustManagerFactory deviceDefaultTrustManagerFactory;

            // Use the CertificateUtils to create a TrustManagerFactory.
            // The TrustManagerFactory is responsible for managing the server-side trust anchors (certificates)
            // used during SSL/TLS handshake to authenticate the server's identity.
            try {
                // Create the TrustManagerFactory using your custom trust store
                // (you can pass null for default trust managers)
                trustManagerFactory =
                        certificateUtils.initTrustManager(null);

                // Obtain the default TrustManagerFactory with the device's default trust store
                deviceDefaultTrustManagerFactory =
                        certificateUtils.getDefaultTrustManagers();


                // Get the array of TrustManagers from the device's default trust store
                TrustManager[] deviceDefaultTrustManagers =
                        deviceDefaultTrustManagerFactory.getTrustManagers();

                // Get the array of TrustManagers from your custom trust store
                TrustManager[] customTrustManagers =
                        trustManagerFactory.getTrustManagers();

                // Concatenate the arrays of TrustManagers from both sources into a single array
                allTrustManagers = Stream.concat(
                                Arrays.stream(deviceDefaultTrustManagers),
                                Arrays.stream(customTrustManagers))
                        .toArray(TrustManager[]::new);

            } catch (java.security.cert.CertificateException ce) {
                throw new CertificateException("error while creating Certificate", ce);
            } catch (IOException ioe) {
                throw new CertificateException("io error with the server-certificate file.", ioe);
            } catch (NoSuchAlgorithmException nsae) {
                throw new CertificateException("Unknown algorithm: X.509 || RSA", nsae);
            } catch (KeyStoreException kse) {
                throw new CertificateException("Error while initializing KeyStore with server-certificates", kse);
            }

            SSLContext sslContext;
            try {
                // Get an instance of SSLContext for TLS protocols
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    // For API level 29 and above, use "TLSv1.3"
                    sslContext = SSLContext.getInstance("TLSv1.3");
                } else {
                    // For API level below 29, use "TLSv1.2"
                    sslContext = SSLContext.getInstance("TLSv1.2");
                }

                sslContext.init(
                        keyManagerFactory.getKeyManagers(),
                        allTrustManagers,
                        new SecureRandom());

            } catch (NoSuchAlgorithmException nsae) {
                throw new SocketException("unknown ssl algorithm: TLSv1.?", nsae);
            } catch (KeyManagementException kme) {
                throw new SocketException("error while creating connection context", kme);
            }

            try {
                // Use the SSLContext to create SSLSockets
                SocketFactory factory = sslContext.getSocketFactory();
                SSLSocket sslSocket =
                        (SSLSocket) factory.createSocket(host, port);

                // Use as client
                sslSocket.setKeepAlive(true);
                sslSocket.setUseClientMode(true);
                // sslSocket.setEnabledCipherSuites(
                // new String[]{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"});

                HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
                SSLSession sslSession = sslSocket.getSession();

                if (!hv.verify(host, sslSession)) {
                    throw new SocketException("Error while verifying secure socket to " + url);
                }

                socket = sslSocket;
            } catch (UnknownHostException uhe) {
                throw new SocketException("unknown host: " + host, uhe);
            } catch (IOException ioe) {
                throw new SocketException("error while creating secure socket to " + url, ioe);
            }
        } else {
            throw new SocketException("unsupported protocol: " + scheme);
        }

        return socket;
    }

    /**
     * Blocks until both threads exit. The actual close must be triggered separately. This is just a
     * convenience method to make sure everything shuts down, if desired.
     *
     * @throws InterruptedException
     */
    public void blockClose() throws InterruptedException {
        // If the thread is new, it will never run, since we closed the connection before we actually
        // connected
        if (writer.getInnerThread().getState() != Thread.State.NEW) {
            writer.getInnerThread().join();
        }
        getInnerThread().join();
    }

    private void runReader() {
        try {
            java.net.Socket socket = createSocket();
            synchronized (this) {
                this.socket = socket;
                if (this.state == State.DISCONNECTED) {
                    // The connection has been closed while creating the socket, close it immediately and
                    // return
                    try {
                        this.socket.close();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    this.socket = null;
                    return;
                }
            }

            DataInputStream input = new DataInputStream(socket.getInputStream());
            OutputStream output = socket.getOutputStream();

            output.write(handshake.getHandshake());

            boolean handshakeComplete = false;
            int len = 1000;
            byte[] buffer = new byte[len];
            int pos = 0;
            ArrayList<String> handshakeLines = new ArrayList<String>();

            while (!handshakeComplete) {
                int b = input.read();
                if (b == -1) {
                    throw new SocketException("Connection closed before handshake was complete");
                }
                buffer[pos] = (byte) b;
                pos += 1;

                if (buffer[pos - 1] == 0x0A && buffer[pos - 2] == 0x0D) {
                    String line = new String(buffer, UTF8);
                    if (line.trim().equals("")) {
                        handshakeComplete = true;
                    } else {
                        handshakeLines.add(line.trim());
                    }

                    buffer = new byte[len];
                    pos = 0;
                } else if (pos == 1000) {
                    // This really shouldn't happen, handshake lines are short, but just to be safe...
                    String line = new String(buffer, UTF8);
                    throw new SocketException("Unexpected long line in handshake: " + line);
                }
            }

            handshake.verifyServerStatusLine(handshakeLines.get(0));
            handshakeLines.remove(0);

//            HashMap<String, String> lowercaseHeaders = new HashMap<String, String>();
//            for (String line : handshakeLines) {
//                String[] keyValue = line.split(": ", 2);
//                lowercaseHeaders.put(
//                        keyValue[0].toLowerCase(Locale.US), keyValue[1].toLowerCase(Locale.US));
//            }
//            handshake.validateServerHandshakeHeaders(lowercaseHeaders);


            writer.setOutput(output);
            receiver.setInput(input);
            state = Socket.State.CONNECTED;
            writer.getInnerThread().start();
            eventHandler.onOpen();
            receiver.run();
        } catch (SocketException wse) {
            eventHandler.onError(wse);
        } catch (Throwable e) {
            e.printStackTrace();
            eventHandler.onError(new SocketException("error while connecting: " + e.getMessage(), e));
        } finally {
            close();
        }
    }

    Thread getInnerThread() {
        return innerThread;
    }
}