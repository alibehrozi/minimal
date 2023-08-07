package com.github.alibehrozi.minimal.network.certificate;

public class CertificateException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public CertificateException(String message) {
        super(message);
    }

    public CertificateException(String message, Throwable cause) {
        super(message, cause);
    }
}
