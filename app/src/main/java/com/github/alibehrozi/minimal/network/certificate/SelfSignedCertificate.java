package com.github.alibehrozi.minimal.network.certificate;


import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.BufferedWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.Period;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class SelfSignedCertificate {

    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();
    private static final boolean IS_CA = false;
    private static final List<String> sanHostNames = Collections.singletonList("localhost");
    private static final List<String> sanIpAddresses = Collections.singletonList("127.0.0.1");

    private final KeyPair keyPair; // not sure if this is needed.
    private final X509Certificate certificate;

    public SelfSignedCertificate(final KeyPair keyPair, final X509Certificate certificate) {
        this.keyPair = keyPair;
        this.certificate = certificate;
    }

    public static SelfSignedCertificate generate() throws GeneralSecurityException, IOException, OperatorCreationException {

        final KeyPair keyPair = generateKeyPair();
        return new SelfSignedCertificate(keyPair, createSelfSignedCertificate(keyPair));

    }

    private static KeyPair generateKeyPair() throws GeneralSecurityException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private static X509Certificate createSelfSignedCertificate(final KeyPair keyPair)
            throws IOException, GeneralSecurityException, OperatorCreationException {
        // Generate a random serial number for the certificate
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        // Set the certificate's validity period (1 year)
        Date startDate = Date.from(Instant.now());
        Date expiryDate = Date.from(Instant.now().plus(Period.ofDays(10)));

        // Create a new X.509 version 3 certificate builder
        final X509v3CertificateBuilder v3CertificateBuilder =
                new JcaX509v3CertificateBuilder(
                        new X500Name("CN=Self-Signed"), // Issuer name,
                        serialNumber,
                        startDate,
                        expiryDate,
                        new X500Name("CN=Self-Signed"), // Subject name,
                        keyPair.getPublic() // Public key
                );

        // extensions
        v3CertificateBuilder.addExtension(
                Extension.basicConstraints, true, new BasicConstraints(IS_CA));
        v3CertificateBuilder.addExtension(
                Extension.subjectAlternativeName, false, getSubjectAlternativeNames());

        // Sign the certificate with the private key to make it self-signed
        final ContentSigner contentSigner =
                new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());

        // Build the certificate and Convert the certificate holder to a JCA X.509 certificate
        return new JcaX509CertificateConverter()
                .setProvider(BOUNCY_CASTLE_PROVIDER)
                .getCertificate(v3CertificateBuilder.build(contentSigner));
    }

    private static GeneralNames getSubjectAlternativeNames() {
        final List<GeneralName> hostGeneralNames =
                sanHostNames.stream()
                        .map(hostName -> new GeneralName(GeneralName.dNSName, hostName))
                        .collect(Collectors.toList());
        final List<GeneralName> ipGeneralNames =
                sanIpAddresses.stream()
                        .map(ipAddress -> new GeneralName(GeneralName.iPAddress, ipAddress))
                        .collect(Collectors.toList());
        final GeneralName[] generalNames =
                Stream.of(hostGeneralNames, ipGeneralNames)
                        .flatMap(Collection::stream)
                        .toArray(GeneralName[]::new);

        return new GeneralNames(generalNames);
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void writePrivateKeyToFile(final Path outputFile) throws IOException {
        try (final BufferedWriter writer = Files.newBufferedWriter(outputFile, StandardCharsets.UTF_8);
             final PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(new PemObject("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
        }
    }

    public void writeCertificateToFile(final Path pemFile)
            throws IOException, CertificateEncodingException {
        try (final BufferedWriter writer = Files.newBufferedWriter(pemFile, StandardCharsets.UTF_8);
             final PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
        }
    }
}