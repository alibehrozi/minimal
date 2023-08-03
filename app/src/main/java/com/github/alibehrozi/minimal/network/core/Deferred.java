package com.github.alibehrozi.minimal.network.core;

import com.github.alibehrozi.minimal.network.core.annotations.NotNull;

/**
 * Represents a continuation-style dependency.
 *
 * <p>The motivation for it is to model optional dependencies that may become available in the
 * future and once they do, the depender will get notified automatically via the registered {@link
 * DeferredHandler}.
 *
 * <p>Example:
 *
 * <pre>{@code
 * class Foo {
 *   Foo(Deferred<Bar> bar) {
 *     bar.whenAvailable(barProvider -> {
 *       // automatically called when Bar becomes available
 *       use(barProvider.get());
 *     });
 *   }
 * }
 * }</pre>
 */
public interface Deferred<T> {
    /** Used by dependers to register their callbacks. */
    interface DeferredHandler<T> {

        void handle(Provider<T> provider);
    }

    /** Register a callback that is executed once {@link T} becomes available */
    void whenAvailable(@NotNull DeferredHandler<T> handler);
}