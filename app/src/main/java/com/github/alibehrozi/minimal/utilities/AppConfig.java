package com.github.alibehrozi.minimal.utilities;

import com.github.alibehrozi.minimal.utilities.logging.AndroidLogger;
import com.github.alibehrozi.minimal.utilities.logging.LogWrapper;
import com.github.alibehrozi.minimal.utilities.logging.Logger;

import java.util.List;

public class AppConfig {

    protected Logger logger;
    protected List<String> loggedComponents;
    protected Logger.Level logLevel = Logger.Level.DEBUG;

    public AppConfig() {
        ensureLogger();
    }

    /**
     * If you would like to provide a custom log target, pass an object that implements the {@link
     * Logger Logger} interface.
     *
     * @hide
     * @param logger The custom logger that will be called with all log messages
     */
    public synchronized void setLogger(Logger logger) {
        this.logger = logger;
    }

    /**
     * By default, this is set to {@link Logger.Level#INFO INFO}. This includes any internal errors
     * ({@link Logger.Level#ERROR ERROR}) and any security debug messages ({@link Logger.Level#INFO
     * INFO}) that the client receives. Set to {@link Logger.Level#DEBUG DEBUG} to turn on the
     * diagnostic logging, and {@link Logger.Level#NONE NONE} to disable all logging.
     *
     * @param logLevel The desired minimum log level
     */
    public synchronized void setLogLevel(Logger.Level logLevel) {
        switch (logLevel) {
            case DEBUG:
                this.logLevel = Logger.Level.DEBUG;
                break;
            case INFO:
                this.logLevel = Logger.Level.INFO;
                break;
            case WARN:
                this.logLevel = Logger.Level.WARN;
                break;
            case ERROR:
                this.logLevel = Logger.Level.ERROR;
                break;
            case NONE:
                this.logLevel = Logger.Level.NONE;
                break;
            default:
                throw new IllegalArgumentException("Unknown log level: " + logLevel);
        }
    }

    /**
     * Used primarily for debugging. Limits the debug output to the specified components. By default,
     * this is null, which enables logging from all components. Setting this explicitly will also set
     * the log level to {@link Logger.Level#DEBUG DEBUG}.
     *
     * @param debugComponents A list of components for which logs are desired, or null to enable all
     *     components
     */
    public synchronized void setDebugLogComponents(List<String> debugComponents) {
        setLogLevel(Logger.Level.DEBUG);
        loggedComponents = debugComponents;
    }

    public List<String> getOptDebugLogComponents() {
        return this.loggedComponents;
    }

    public Logger.Level getLogLevel() {
        return this.logLevel;
    }

    public Logger getLogger() {
        return this.logger;
    }

    public LogWrapper getLogger(String component) {
        return new LogWrapper(logger, component);
    }

    public LogWrapper getLogger(String component, String prefix) {
        return new LogWrapper(logger, component, prefix);
    }

    private void ensureLogger() {
        if (logger == null) {
            logger = newLogger(logLevel, loggedComponents);
        }
    }

    public Logger newLogger(
            Logger.Level component,
            List<String> enabledComponents) {
        return new AndroidLogger(component, enabledComponents);
    }

}
