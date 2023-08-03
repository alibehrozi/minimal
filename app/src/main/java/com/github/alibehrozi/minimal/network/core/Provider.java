package com.github.alibehrozi.minimal.network.core;


/** Provides instances of T. */
public interface Provider<T> {
    /** Provides a fully constructed instance of T. */
    T get();
}