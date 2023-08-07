package com.github.alibehrozi.minimal.network.certificate;

import static com.github.alibehrozi.minimal.AppLoader.getContext;

import com.github.alibehrozi.minimal.network.tubesock.SocketException;

import org.bouncycastle.operator.OperatorCreationException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Locale;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

public class CertificateUtils {

    /**
     * Creates a new empty trust store.
     * Initializes the default TrustManagerFactory with the system default trust store and returns it.
     *
     * @return The default TrustManagerFactory with the system default trust store.
     * @throws java.security.cert.CertificateException if there is an error with certificates.
     * @throws IOException                             if there is an I/O error.
     * @throws NoSuchAlgorithmException                if the specified algorithm is not available.
     * @throws KeyStoreException                       if there is an error with the keystore.
     */
    public TrustManagerFactory getDefaultTrustManagers() throws
            java.security.cert.CertificateException,
            IOException,
            NoSuchAlgorithmException,
            KeyStoreException {

        // Load an empty trust store
        KeyStore ksTrust = loadEmptyTrustStore(null);

        // Obtain the default TrustManagerFactory using the default algorithm
        TrustManagerFactory defaultTrustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        // Initialize the default TrustManagerFactory with the system default trust store
        defaultTrustManagerFactory.init(ksTrust);

        return defaultTrustManagerFactory;
    }

    /**
     * Creates a KeyManagerFactory with the provided password and the loaded or newly created KeyStore.
     *
     * @param password The password to protect the KeyStore.
     * @return The KeyManagerFactory containing the KeyManagers.
     * @throws CertificateException      If there is an error with the certificate.
     * @throws IOException               If there is an I/O error with the file.
     * @throws NoSuchAlgorithmException  If the cryptographic algorithm is not available.
     * @throws UnrecoverableKeyException If the key cannot be recovered due to an invalid password.
     * @throws KeyStoreException         If there is an error with the KeyStore.
     */
    public KeyManagerFactory initKeyManager(char[] password) throws
            GeneralSecurityException,
            IOException,
            OperatorCreationException {

        // Loads the KeyStore from a file or creates a new one if the file doesn't exist
        KeyStore ksKeys = loadKeyStore(password);

        // if its Empty keystore
        if (ksKeys.size() == 0) {
            throw new KeyStoreException("Failed to load or create KeyStore");
        }

        // KeyManagers decide which key material to use
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(ksKeys, password);

        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        if (keyManagers.length != 1 || !(keyManagers[0] instanceof X509KeyManager)) {
            throw new CertificateException("Unexpected default key managers: " + Arrays.toString(keyManagers));
        }

        return keyManagerFactory;
    }

    /**
     * Creates a TrustManagerFactory with the provided password and the loaded or newly created TrustStore.
     *
     * @param password The password to protect the TrustStore.
     * @return The TrustManagerFactory containing the TrustManagers.
     * @throws CertificateException     If there is an error with the certificate.
     * @throws IOException              If there is an I/O error with the file.
     * @throws NoSuchAlgorithmException If the cryptographic algorithm is not available.
     * @throws KeyStoreException        If there is an error with the KeyStore.
     */
    public TrustManagerFactory initTrustManager(char[] password, Certificate... certificates) throws
            java.security.cert.CertificateException,
            IOException,
            NoSuchAlgorithmException,
            KeyStoreException,
            SocketException {

        // Loads the TrustStore from a file or creates a new one if the file doesn't exist
        KeyStore ksTrust = loadTrustStore(password);

        // Load server certificate
        for (Certificate certificate : certificates) {
            String certificateAlias = String.format(
                    Locale.US,
                    "certificate-%d",
                    certificate.hashCode());

            if (ksTrust.containsAlias(certificateAlias))
                continue;
            ksTrust.setCertificateEntry(certificateAlias, certificate);
        }

        // TrustManagers decide whether to allow connections
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(ksTrust);

        return trustManagerFactory;
    }

    /**
     * Loads the KeyStore from a file or creates a new one if the file doesn't exist. If the
     * KeyStore file already exists, it is loaded with the provided password. If the file
     * doesn't exist, a new KeyStore is created and initialized with a self-signed certificate,
     * and then saved to the file with the provided password.
     *
     * @param password The password to protect the KeyStore.
     * @return The loaded or newly created KeyStore.
     * @throws CertificateException     If there is an error with the certificate.
     * @throws IOException              If there is an I/O error with the file.
     * @throws NoSuchAlgorithmException If the cryptographic algorithm is not available.
     * @throws KeyStoreException        If there is an error with the KeyStore.
     */
    private KeyStore loadKeyStore(char[] password) throws
            GeneralSecurityException,
            IOException,
            OperatorCreationException {

        // initialize the key
        KeyStore ksKeys = KeyStore.getInstance(KeyStore.getDefaultType());

        // Check if the KeyStore file exists
        File keystoreFile = new File(getContext().getFilesDir() + "/keystore.jks");
        if (keystoreFile.exists()) {

            // If the file exists, load the KeyStore
            try (FileInputStream keyStream = new FileInputStream(keystoreFile)) {
                ksKeys.load(keyStream, password);
            }

        } else {

            // If the file doesn't exist, create a new KeyStore and save it
            try (FileOutputStream keyStream = new FileOutputStream(keystoreFile)) {
                // Load an empty KeyStore
                ksKeys.load(null, null);

                // Save the KeyStore with the provided password
                ksKeys.store(keyStream, password);
            }
        }

        if (!ksKeys.containsAlias("clientCert")) {
            final SelfSignedCertificate selfSignedCert = SelfSignedCertificate.generate();
            final X509Certificate clientCert = selfSignedCert.getCertificate();

            // initialize client SSL context (client authorization)
            ksKeys.setCertificateEntry("clientCert", clientCert);
            ksKeys.setKeyEntry("client",
                    selfSignedCert.getKeyPair().getPrivate(),
                    password,
                    new X509Certificate[]{clientCert});
        }

        return ksKeys;
    }

    /**
     * Loads the TrustStore from a file or creates a new one if the file doesn't exist. If the
     * TrustStore file already exists, it is loaded with the provided password. If the file
     * doesn't exist, a new TrustStore is created and initialized, and then saved to the file
     * with the provided password.
     *
     * @param password The password to protect the TrustStore.
     * @return The loaded or newly created TrustStore.
     */
    private KeyStore loadTrustStore(char[] password) throws
            java.security.cert.CertificateException,
            IOException,
            NoSuchAlgorithmException,
            KeyStoreException {

        KeyStore ksTrust = KeyStore.getInstance(KeyStore.getDefaultType());

        // Check if the KeyStore file exists
        File keystoreFile = new File(getContext().getFilesDir() + "/trustStore.jks");
        if (keystoreFile.exists()) {

            // If the file exists, load the KeyStore
            try (FileInputStream keyStream = new FileInputStream(keystoreFile)) {
                ksTrust.load(keyStream, password);
            } catch (FileNotFoundException fnfe) {
                throw new CertificateException("error while opening keystore for certificate", fnfe);
            }

        } else {

            // If the file doesn't exist, create a new KeyStore and save it
            try (FileOutputStream keyStream = new FileOutputStream(keystoreFile)) {
                // Load an empty KeyStore
                ksTrust.load(null, null);

                // Save the KeyStore with the provided password
                ksTrust.store(keyStream, password);
            } catch (FileNotFoundException fnfe) {
                throw new CertificateException("error while creating keystore for certificate", fnfe);
            }
        }

        return ksTrust;
    }

    /**
     * Loads the TrustStore from a file or creates a new one if the file doesn't exist. If the
     * TrustStore file already exists, it is loaded with the provided password. If the file
     * doesn't exist, a new TrustStore is created and initialized, and then saved to the file
     * with the provided password.
     *
     * @param password The password to protect the TrustStore.
     * @return The loaded or newly created TrustStore.
     */
    private KeyStore loadEmptyTrustStore(char[] password) throws
            java.security.cert.CertificateException,
            IOException,
            NoSuchAlgorithmException,
            KeyStoreException {

        KeyStore ksTrust = KeyStore.getInstance(KeyStore.getDefaultType());

        // Load an empty KeyStore
        ksTrust.load(null, password);

        return ksTrust;
    }

    /**
     * Remove certificates form TrustStore.
     *
     * @param password    The password to protect the TrustStore.
     * @param certificates The certificates to remove
     * @return The TrustManagerFactory containing the TrustManagers.
     * @throws IOException              If there is an I/O error with the file.
     * @throws KeyStoreException        If there is an error with the KeyStore.
     */
    private boolean removeTrustedCertificate(char[] password, Certificate... certificates) throws
            IOException,
            KeyStoreException {

        KeyStore ksTrust = KeyStore.getInstance(KeyStore.getDefaultType());

        // Check if the KeyStore file exists
        File keystoreFile = new File(getContext().getFilesDir() + "/trustStore.jks");
        if (!keystoreFile.exists()) {
            throw new FileNotFoundException("error while removing a certificate for keystore");
        }

        // Load server certificate
        for (Certificate certificate : certificates) {
            String certificateAlias = String.format(
                    Locale.US,
                    "certificate-%d",
                    certificate.hashCode());

            if (!ksTrust.containsAlias(certificateAlias))
                continue;
            ksTrust.deleteEntry(certificateAlias);
        }
        return true;
    }

}
