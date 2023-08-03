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

import static com.github.alibehrozi.minimal.AppLoader.getInputStreamFromAssets;

import com.github.alibehrozi.minimal.network.ConnectionContext;
import com.github.alibehrozi.minimal.network.core.annotations.Nullable;
import com.github.alibehrozi.minimal.utilities.logging.LogWrapper;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;


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

            // Create and initialize the SSLContext with key material
            char[] passphrase = "passphrase".toCharArray();
            KeyStore ksKeys;
            KeyStore ksTrust;
            try {
                // initialize the key and trust material
                ksKeys = KeyStore.getInstance(KeyStore.getDefaultType());
                ksKeys.load(null, null);

                ksTrust = KeyStore.getInstance(KeyStore.getDefaultType());
                ksTrust.load(null, null);

            } catch (CertificateException cre) {
                throw new SocketException("error while creating keystore certificate", cre);
            } catch (KeyStoreException kse) {
                throw new SocketException("error while creating keystore", kse);
            } catch (NoSuchAlgorithmException nsae) {
                throw new SocketException("unknown algorithm: JKS", nsae);
            } catch (IOException ioe) {
                throw new SocketException("error while opening certificate to " + url, ioe);
            }

            KeyManagerFactory keyManagerFactory;
            try {
                // Load client certificate
                InputStream certificateStream = getInputStreamFromAssets("client-cert.pem");
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                X509Certificate clientCert = (X509Certificate) certificateFactory.generateCertificate(certificateStream);

                // Load client private key
                InputStream keyInputStream = getInputStreamFromAssets("client-key.pem");
                PrivateKey clientPrivateKey = PrivateKeyReader.getPrivateKey(keyInputStream);

                // initialize client SSL context (client authorization)
                ksKeys.setCertificateEntry("client", clientCert);
                ksKeys.setKeyEntry("client",
                        clientPrivateKey,
                        null,
                        new X509Certificate[]{clientCert});

                // KeyManagers decide which key material to use
                keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                keyManagerFactory.init(ksKeys, null);

                KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

                if (keyManagers.length != 1 || !(keyManagers[0] instanceof X509KeyManager)) {
                    throw new SocketException("Unexpected default key managers:"
                            + Arrays.toString(keyManagers));
                }

            } catch (UnrecoverableKeyException uke) {
                throw new SocketException("error while creating keyManagerFactory", uke);
            } catch (CertificateException ce) {
                throw new SocketException("error while creating CertificateFactory", ce);
            } catch (IOException ioe) {
                throw new SocketException("error while opening client-cert from assets", ioe);
            } catch (NoSuchAlgorithmException nsae) {
                throw new SocketException("unknown algorithm: X.509 || RSA", nsae);
            } catch (InvalidKeySpecException ikse) {
                throw new SocketException("error while initializing keystore with invalid key spec", ikse);
            } catch (KeyStoreException kse) {
                throw new SocketException("error while initializing keystore with client-certificates", kse);
            } catch (GeneralSecurityException gse) {
                throw new SocketException("error while initializing keystore with client-certificates SecurityException", gse);
            }

            TrustManagerFactory trustManagerFactory;
            try {

                // Load server certificate
                InputStream certificateStream = getInputStreamFromAssets("server-cert.pem");
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                Collection<? extends Certificate> certificates =
                        certificateFactory.generateCertificates(certificateStream);

                if (certificates.isEmpty()) {
                    throw new SocketException("expected non-empty set of trusted certificates");
                }

                int index = 0;
                for (Certificate certificate : certificates) {
                    String certificateAlias = Integer.toString(index++);
                    ksTrust.setCertificateEntry(certificateAlias, certificate);
                }

                // TrustManagers decide whether to allow connections
                trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(ksTrust);

                TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();

                if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
                    throw new SocketException("Unexpected default trust managers:"
                            + Arrays.toString(trustManagers));
                }

            } catch (NoSuchAlgorithmException nsae) {
                throw new SocketException("unknown algorithm: " + TrustManagerFactory.getDefaultAlgorithm(), nsae);
            } catch (CertificateException ce) {
                throw new SocketException("error while creating CertificateFactory", ce);
            } catch (KeyStoreException kse) {
                throw new SocketException("error while creating keystore", kse);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            SSLContext sslContext;
            try {
                // TODO : use "TLSv1.3" for api > 29
                // Get an instance of SSLContext for TLS protocols

                // An SSLContext is a collection of ciphers, protocol versions,
                // trusted certificates, TLS options, TLS extensions etc.
                // Since it is very common to have multiple connections with the same settings
                // they are put together in a context and the relevant SSL connections
                // are then created based on this context.
                //
                // The SSLSocket is used to create an SSLEngine which is used to
                // establish a secure connection between two endpoints.
                sslContext = SSLContext.getInstance("TLSv1.2");
                sslContext.init(
                        keyManagerFactory.getKeyManagers(),
                        trustManagerFactory.getTrustManagers(),
                        new SecureRandom());

            } catch (NoSuchAlgorithmException nsae) {
                throw new SocketException("unknown algorithm: TLSv1.2", nsae);
            } catch (KeyManagementException kme) {
                throw new SocketException("error while creating connection context", kme);
            }

            try {
                SocketFactory factory = sslContext.getSocketFactory();
                SSLSocket sslSocket =
                        (SSLSocket) factory.createSocket(host, port);

                // Use as client
                sslSocket.setKeepAlive(true);
                sslSocket.setUseClientMode(true);
//                sslSocket.setEnabledCipherSuites(
//                        new String[]{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"});

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
        }  catch (Exception e) {
            e.printStackTrace();
            eventHandler.onError(new SocketException("error while connecting: " + e.getMessage(), e));
        } catch (Throwable t) {
            t.printStackTrace();
            eventHandler.onError(new SocketException("error while connecting: " + t.getMessage(), t));
        } finally {
            close();
        }
    }

    Thread getInnerThread() {
        return innerThread;
    }
}