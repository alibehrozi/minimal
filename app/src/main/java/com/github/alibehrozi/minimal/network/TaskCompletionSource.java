package com.github.alibehrozi.minimal.network;

/**
 * Custom TaskCompletionSource class to create and control Task instances.
 *
 * @param <T> The result type of the Task.
 */
public class TaskCompletionSource<T> {

    private final Task<T> task;

    public TaskCompletionSource() {
        task = new Task<>();
    }

    /**
     * Sets the result of the Task.
     *
     * @param result The result to be set.
     * @throws IllegalStateException if the Task is already completed or canceled.
     */
    public void setResult(T result) {
        task.setResult(result);
    }

    /**
     * Sets an exception as the result of the Task.
     *
     * @param exception The exception to be set.
     * @throws IllegalStateException if the Task is already completed or canceled.
     */
    public void setException(Exception exception) {
        task.setException(exception);
    }

    /**
     * Gets the Task associated with this instance.
     *
     * @return The Task associated with this instance.
     */
    public Task<T> getTask() {
        return task;
    }
}