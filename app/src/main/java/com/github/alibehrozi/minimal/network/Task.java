package com.github.alibehrozi.minimal.network;


import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;


/**
 * Custom Task class to represent asynchronous operations.
 *
 * @param <T> The result type of the Task.
 */
public class Task<T> {
    private T result;
    private Exception exception;
    private boolean isCompleted;
    private boolean isCancelled;
    private boolean isSuccessful;
    // List of listeners to be notified when the task is complete
    private final List<OnCompleteListener<T>> onCompleteListeners = new ArrayList<>();

    private final Executor executor = Executors.newCachedThreadPool();

    /**
     * Sets the result of the Task.
     *
     * @param result The result to be set.
     * @throws IllegalStateException if the Task is already completed or canceled.
     */
    public synchronized void setResult(T result) {
        if (isCompleted || isCancelled) {
            throw new IllegalStateException("Task is already completed or canceled.");
        }
        this.result = result;
        isCompleted = true;
        isSuccessful = true;
        notifyComplete();
    }

    /**
     * Sets an exception as the result of the Task.
     *
     * @param exception The exception to be set.
     * @throws IllegalStateException if the Task is already completed or canceled.
     */
    public synchronized void setException(Exception exception) {
        if (isCompleted || isCancelled) {
            throw new IllegalStateException("Task is already completed or canceled.");
        }
        this.exception = exception;
        isCompleted = true;
        notifyComplete();
    }

    /**
     * Cancels the Task.
     *
     * @param mayInterruptIfRunning Whether the Task's execution should be interrupted if running.
     * @return true if the Task was canceled successfully, false otherwise.
     */
    public synchronized boolean cancel(boolean mayInterruptIfRunning) {
        if (isCompleted || isCancelled) {
            return false;
        }
        isCancelled = true;
        notifyComplete();
        return true;
    }

    /**
     * Checks if the Task is completed.
     *
     * @return true if the Task is completed, false otherwise.
     */
    public synchronized boolean isCompleted() {
        return isCompleted;
    }

    /**
     * Checks if the Task is canceled.
     *
     * @return true if the Task is canceled, false otherwise.
     */
    public synchronized boolean isCancelled() {
        return isCancelled;
    }

    /**
     * Checks if the Task was successful.
     *
     * @return true if the Task was successful, false otherwise.
     */
    public synchronized boolean isSuccessful() {
        return isSuccessful;
    }

    /**
     * Gets the exception associated with the completed Task, if any.
     *
     * @return The exception associated with the Task, or null if the Task completed successfully.
     */
    public Exception getException() {
        try {
            this.getResult();
        } catch (Exception e) {
            return e;
        }
        return null;
    }

    /**
     * Gets the result of the Task.
     *
     * @return The result of the Task.
     */
    public synchronized T getResult() {
        if (isCancelled() || !isCompleted() || !isSuccessful()) {
            return null;
        }
        if (exception != null) {
            return null;
        }
        return result;
    }

    /**
     * Executes a task on the background thread.
     *
     * @param callable  The task to be executed.
     * @param <TResult> The result type of the task.
     * @return The Task representing the asynchronous operation.
     */
    public static <TResult> Task<TResult> runInBackground(Callable<TResult> callable) {
        Task<TResult> task = new Task<>();
        task.executor.execute(() -> {
            try {
                TResult result = callable.call();
                task.setResult(result);
            } catch (Exception e) {
                task.setException(e);
            }
        });
        return task;
    }

    /**
     * Executes a task on the UI thread.
     *
     * @param callable  The task to be executed.
     * @param <TResult> The result type of the task.
     * @return The Task representing the asynchronous operation.
     */
    public static <TResult> Task<TResult> runOnUiThread(Callable<TResult> callable) {
        Task<TResult> task = new Task<>();
        task.executor.execute(() -> {
            try {
                TResult result = callable.call();
                task.setResult(result);
            } catch (Exception e) {
                task.setException(e);
            }
        });
        return task;
    }

    /**
     * Notifies all registered listeners that the task is complete
     */
    private void notifyComplete() {
        for (OnCompleteListener<T> listener : onCompleteListeners) {
            listener.onComplete(this, result, exception);
        }
    }

    /**
     * Listens for the completion of the Task.
     *
     * @param listener The completion listener to be invoked.
     */
    public void addOnCompleteListener(OnCompleteListener<T> listener) {
        onCompleteListeners.add(listener);
    }

    /**
     * Method to register a listener to be notified when the task is complete,
     * and specify the ExecutorService for running the listener
     * @param executorService
     * @param listener
     */
    public void addOnCompleteListener(ExecutorService executorService, OnCompleteListener<T> listener) {
        onCompleteListeners.add((task, result1, exception1) ->
                executorService.submit(() -> listener.onComplete(task, result1, exception1)));
    }

    /**
     * Listens for the successful completion of the Task.
     *
     * @param listener The success listener to be invoked.
     */
    public Task<T> addOnSuccessListener(OnSuccessListener<T> listener) {
        addOnCompleteListener((task, result1, exception1) -> {
            if (task.isSuccessful() || task.isCompleted()) {
                listener.onSuccess(result1);
            }
        });
        return this;
    }

    /**
     * Overloaded method to register a success listener with a specific ExecutorService
     *
     * @param executorService
     * @param listener
     * @return
     */
    public Task<T> addOnSuccessListener(ExecutorService executorService, OnSuccessListener<T> listener) {
        addOnCompleteListener(executorService, (task, result1, exception1) -> {
            if (task.isSuccessful() || task.isCompleted()) {
                listener.onSuccess(result1);
            }
        });
        return this;
    }

    /**
     * Listens for the failure of the Task.
     *
     * @param listener The failure listener to be invoked.
     */
    public Task<T> addOnFailureListener(OnFailureListener listener) {
        addOnCompleteListener((task, result, exception) -> {
            if (exception != null || !task.isSuccessful() || !task.isCompleted() || task.isCancelled()) {
                listener.onFailure(exception);
            }
        });
        return this;
    }

    /**
     * Overloaded method to register a failure listener with a specific ExecutorService
     */
    public Task<T> addOnFailureListener(ExecutorService executorService, OnFailureListener listener) {
        addOnCompleteListener(executorService, (task, result1, exception) -> {
            if (exception != null || !task.isSuccessful() || !task.isCompleted() || task.isCancelled()) {
                listener.onFailure(task.getException());
            }
        });
        return this;
    }


    /**
     * Interface for a task completion listener.
     *
     * @param <T> The result type of the Task.
     */
    public interface OnCompleteListener<T> {
        /**
         * Called when the Task is completed.
         *
         * @param task      The completed Task.
         * @param result    The result of the Task (if successful), otherwise null.
         * @param exception The exception thrown by the Task (if unsuccessful), otherwise null.
         */
        void onComplete(Task<T> task, T result, Exception exception);
    }

    /**
     * Interface for a success listener.
     *
     * @param <T> The result type of the Task.
     */
    public interface OnSuccessListener<T> {
        /**
         * Called when the Task is successful.
         *
         * @param result The result of the Task.
         */
        void onSuccess(T result);
    }

    /**
     * Interface for a failure listener.
     */
    public interface OnFailureListener {
        /**
         * Called when the Task fails.
         *
         * @param exception The exception thrown by the Task.
         */
        void onFailure(Exception exception);
    }

    /**
     * creates a task that completes when all input tasks complete
     */
    @SafeVarargs
    public static <T> Task<List<T>> whenAll(Task<T>... tasks) {
        // Create a new TaskCompletionSource to track the completion of all tasks
        TaskCompletionSource<List<T>> taskCompletionSource = new TaskCompletionSource<>();

        // Count the number of completed tasks
        AtomicInteger completedCount = new AtomicInteger();

        // List to store the results of all tasks
        List<T> results = new ArrayList<>();

        // Method to be called when a task is complete
        Task.OnCompleteListener<T> onCompleteListener = (task, result1, exception1) -> {

            // Synchronize the access to the shared data (completedCount and results)
            synchronized (Task.class) {
                if (exception1 != null) {
                    // If any task encounters an exception, set the main task to fail
                    taskCompletionSource.setException(task.getException());
                } else {
                    // Otherwise, add the result to the list and increment the completed count
                    results.add(result1);
                    completedCount.getAndIncrement();

                    // If all tasks are completed, set the main task to succeed
                    if (completedCount.get() == tasks.length) {
                        taskCompletionSource.setResult(results);
                    }
                }
            }
        };

        // Add the onCompleteListener to all tasks
        for (Task<T> task : tasks) {
            task.addOnCompleteListener(onCompleteListener);
        }

        // Return the main task
        return taskCompletionSource.getTask();
    }
}