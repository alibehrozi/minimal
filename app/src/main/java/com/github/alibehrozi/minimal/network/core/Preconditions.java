package com.github.alibehrozi.minimal.network.core;

public class Preconditions {
    public static <T> T checkNotNull(T reference, String message) {
        if (reference == null) {
            throw new NullPointerException(message);
        }
        return reference;
    }
}