package com.github.alibehrozi.minimal.network;

import static com.github.alibehrozi.minimal.network.ConnectionUtils.hardAssert;

import com.github.alibehrozi.minimal.network.core.ConnectionTokenProvider;
import com.github.alibehrozi.minimal.network.core.DefaultRunLoop;
import com.github.alibehrozi.minimal.network.core.Deferred;
import com.github.alibehrozi.minimal.network.core.GAuthToken;
import com.github.alibehrozi.minimal.network.core.Pair;
import com.github.alibehrozi.minimal.network.core.RetryHelper;
import com.github.alibehrozi.minimal.network.core.TokenProvider;
import com.github.alibehrozi.minimal.network.core.Utilities;
import com.github.alibehrozi.minimal.network.core.Validation;
import com.github.alibehrozi.minimal.network.core.annotations.NotNull;
import com.github.alibehrozi.minimal.network.core.annotations.Nullable;
import com.github.alibehrozi.minimal.network.core.appcheck.InteropAppCheckTokenProvider;
import com.github.alibehrozi.minimal.network.core.auth.InternalAuthProvider;
import com.github.alibehrozi.minimal.network.core.encoding.CustomClassMapper;
import com.github.alibehrozi.minimal.utilities.logging.LogWrapper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class NetworkConnection implements Connection.Delegate, NetworkConnectionInterface {
    private interface ConnectionRequestCallback {
        void onResponse(Map<String, Object> response);
    }

    /**
     * This interface is used as a method of being notified when an operation has been acknowledged by
     * the Database servers and can be considered complete
     *
     * @since 1.1
     */
    public interface CompletionListener {

        /**
         * This method will be triggered when the operation has either succeeded or failed. If it has
         * failed, an error will be given. If it has succeeded, the error will be null
         *
         * @param error A description of any errors that occurred or null on success
         */
        void onComplete(
                @Nullable final NetworkError error);
    }

    private static class OutstandingGet {
        private final Map<String, Object> request;
        private final ConnectionRequestCallback onComplete;
        private boolean sent;

        private OutstandingGet(
                String action, Map<String, Object> request, ConnectionRequestCallback onComplete) {
            this.request = request;
            this.onComplete = onComplete;
            this.sent = false;
        }

        private ConnectionRequestCallback getOnComplete() {
            return onComplete;
        }

        private Map<String, Object> getRequest() {
            return request;
        }

        /**
         * Mark this OutstandingGet as sent. Essentially compare-and-set on the `sent` member.
         *
         * @return true if the OustandingGet wasn't already sent, false if it was.
         */
        private boolean markSent() {
            if (sent) {
                return false;
            }
            sent = true;
            return true;
        }
    }

    private static class OutstandingPut {
        private final String action;
        private final Map<String, Object> request;
        private final RequestResultCallback onComplete;
        private boolean sent;

        private OutstandingPut(
                String action, Map<String, Object> request, RequestResultCallback onComplete) {
            this.action = action;
            this.request = request;
            this.onComplete = onComplete;
        }

        public String getAction() {
            return action;
        }

        public Map<String, Object> getRequest() {
            return request;
        }

        public RequestResultCallback getOnComplete() {
            return onComplete;
        }

        public void markSent() {
            this.sent = true;
        }

        public boolean wasSent() {
            return this.sent;
        }
    }

    private static class OutstandingDisconnect {
        private final String action;
        private final Object data;
        private final RequestResultCallback onComplete;

        private OutstandingDisconnect(
                String action, Object data, RequestResultCallback onComplete) {
            this.action = action;
            this.data = data;
            this.onComplete = onComplete;
        }

        public String getAction() {
            return action;
        }

        public Object getData() {
            return data;
        }

        public RequestResultCallback getOnComplete() {
            return onComplete;
        }
    }

    private enum ConnectionState {
        Disconnected,
        GettingToken,
        Connecting,
        Authenticating,
        Connected
    }

    private static final String REQUEST_ERROR = "error";
    private static final String REQUEST_STATUS = "s";
    private static final String REQUEST_NUMBER = "r";
    private static final String REQUEST_PAYLOAD = "b";
    private static final String REQUEST_COUNTERS = "c";
    private static final String REQUEST_DATA_PAYLOAD = "d";
    private static final String REQUEST_DATA_HASH = "h";
    private static final String REQUEST_CREDENTIAL = "cred";
    private static final String REQUEST_APPCHECK_TOKEN = "token";
    private static final String REQUEST_AUTHVAR = "authvar";
    private static final String REQUEST_ACTION = "a";
    private static final String REQUEST_ACTION_STATS = "s";
    private static final String REQUEST_ACTION_QUERY = "q";
    private static final String REQUEST_ACTION_GET = "g";
    private static final String REQUEST_ACTION_ONDISCONNECT_MERGE = "om";
    private static final String REQUEST_ACTION_ONDISCONNECT_CANCEL = "oc";
    private static final String REQUEST_ACTION_AUTH = "auth";
    private static final String REQUEST_ACTION_APPCHECK = "appcheck";
    private static final String REQUEST_ACTION_GAUTH = "gauth";
    private static final String REQUEST_ACTION_UNAUTH = "unauth";
    private static final String REQUEST_ACTION_UNAPPCHECK = "unappcheck";
    private static final String RESPONSE_FOR_REQUEST = "b";
    private static final String SERVER_ASYNC_ACTION = "a";
    private static final String SERVER_ASYNC_PAYLOAD = "b";
    private static final String SERVER_ASYNC_DATA_UPDATE = "d";
    private static final String SERVER_ASYNC_DATA_MERGE = "m";
    private static final String SERVER_ASYNC_AUTH_REVOKED = "ac";
    private static final String SERVER_ASYNC_APP_CHECK_REVOKED = "apc";
    private static final String SERVER_ASYNC_SECURITY_DEBUG = "sd";
    private static final String SERVER_DATA_UPDATE_BODY = "d";
    private static final String SERVER_DATA_TAG = "t";
    private static final String SERVER_RESPONSE_DATA = "d";
    private static final String INVALID_APP_CHECK_TOKEN = "Invalid appcheck token";
    public static final String DOT_INFO_SERVERTIME_OFFSET = "serverTimeOffset";
    private static final String BASE_URL = "https://uxmx.ir";


    /**
     * Instance of the network connection
     */
    private static volatile NetworkConnectionInterface Instance = null;

    /**
     * Delay after which a established connection is considered successful
     */
    private static final long SUCCESSFUL_CONNECTION_ESTABLISHED_DELAY = 30 * 1000;

    private static final long IDLE_TIMEOUT = 60 * 1000;
    private static final long INIT_TIMEOUT = 60 * 1000;

    /**
     * If auth or appcheck fails repeatedly, we'll assume something is wrong and log a warning / back
     * off.
     */
    private static final long INVALID_TOKEN_THRESHOLD = 3;

    private static final String SERVER_KILL_INTERRUPT_REASON = "server_kill";
    private static final String IDLE_INTERRUPT_REASON = "connection_idle";
    private static final String TOKEN_REFRESH_INTERRUPT_REASON = "token_refresh";
    private static final String USER_REQUEST_INTERRUPT_REASON = "user_request";

    private static long connectionIds = 0;

    private final List<Delegate> listens;
    private final HostInfo hostInfo;
    private String cachedHost;
    private final HashSet<String> interruptReasons = new HashSet<String>();
    private boolean firstConnection = true;
    private long lastConnectionEstablishedTime;
    private Connection realtime;
    private ConnectionState connectionState = ConnectionState.Disconnected;
    private final long writeCounter = 0;
    private final long readCounter = 0;
    private long requestCounter = 0;
    private final Map<Long, ConnectionRequestCallback> requestCBHash;

    private final List<OutstandingDisconnect> onDisconnectRequestQueue;
    private final Map<Long, OutstandingPut> outstandingPuts;
    private final Map<Long, OutstandingGet> outstandingGets;

    private String authToken;
    private boolean forceAuthTokenRefresh;
    private String appCheckToken;
    private boolean forceAppCheckTokenRefresh;
    private final ConnectionContext context;
    private final ConnectionTokenProvider authTokenProvider;
    private final ConnectionTokenProvider appCheckTokenProvider;
    private final ScheduledExecutorService executorService;
    private final LogWrapper logger;
    private final LogWrapper operationLogger;

    private final NetworkConfig defaultConfig;

    private final RetryHelper retryHelper;
    private String lastSessionId;
    /**
     * Counter to check whether the callback is for the last getToken call
     */
    private long currentGetTokenAttempt = 0;

    private int invalidAuthTokenCount = 0;
    private int invalidAppCheckTokenCount = 0;

    private ScheduledFuture<?> inactivityTimer = null;
    private long lastWriteTimestamp;
    private boolean hasOnDisconnects;

    /**
     * Gets the default Instance of the connection
     *
     * @return Instance of the connection
     */
    public static synchronized NetworkConnectionInterface getDefaultInstance() {
        return getInstance(BASE_URL);
    }

    /**
     * Gets a NetworkConnection instance for the specified URL.
     *
     * @param url The URL to the instance you want to access.
     * @return A FirebaseDatabase instance.
     */
    @NotNull
    public static NetworkConnectionInterface getInstance(String url) {

        if (url == null) {
            throw new NullPointerException(
                    "Can't pass null for argument 'url' in " + "FirebaseDatabase.getReferenceFromUrl()");
        }

        synchronized (NetworkConnectionInterface.class) {
            if (Instance == null) {
                Deferred<InternalAuthProvider> authProviderDeferred = handler -> {};
                Deferred<InteropAppCheckTokenProvider> appCheckTokenProviderDeferred = handler -> {};
                NetworkConnectionComponent connectionComponent = new NetworkConnectionComponent(
                        authProviderDeferred,
                        appCheckTokenProviderDeferred);

                Instance = connectionComponent.get(Utilities.parseUrl(url));
            }

            return Instance;
        }
    }

    NetworkConnection(HostInfo info, NetworkConfig defaultConfig) {
        this.defaultConfig = defaultConfig;
        this.context = defaultConfig.getConnectionContext();
        this.executorService = context.getExecutorService();
        this.authTokenProvider = context.getAuthTokenProvider();
        this.appCheckTokenProvider = context.getAppCheckTokenProvider();
        this.hostInfo = info;
        this.listens = new ArrayList<>();
        this.requestCBHash = new HashMap<>();
        this.outstandingPuts = new HashMap<>();
        this.outstandingGets = new ConcurrentHashMap<>();
        this.onDisconnectRequestQueue = new ArrayList<>();
        this.retryHelper =
                new RetryHelper.Builder(this.executorService, context.getLogger(), "ConnectionRetryHelper")
                        .withMinDelayAfterFailure(1000)
                        .withRetryExponent(1.3)
                        .withMaxDelay(30 * 1000)
                        .withJitterFactor(0.7)
                        .build();

        long connId = connectionIds++;
        this.logger = new LogWrapper(context.getLogger(), "PersistentConnection", "pc_" + connId);
        this.lastSessionId = null;

        this.operationLogger = defaultConfig.getLogger("RepoOperation");

        // Kick off any expensive additional initialization
        this.executorService.schedule(this::deferredInitialization, 0, TimeUnit.MILLISECONDS);

        doIdleCheck();
    }

    /**
     * Defers any initialization that is potentially expensive (e.g. disk access) and must be run on
     * the run loop
     */
    private void deferredInitialization() {
        defaultConfig
                .getAuthTokenProvider()
                .addTokenChangeListener(
                        ((DefaultRunLoop) defaultConfig.getRunLoop()).getExecutorService(),
                        new TokenProvider.TokenChangeListener() {
                            @Override
                            public void onTokenChange() {
                                operationLogger.debug("Auth token changed, triggering auth token refresh");
                                refreshAuthToken();
                            }

                            @Override
                            public void onTokenChange(String token) {
                                operationLogger.debug("Auth token changed, triggering auth token refresh");
                                refreshAuthToken(token);
                            }
                        });

        defaultConfig
                .getAppCheckTokenProvider()
                .addTokenChangeListener(
                        ((DefaultRunLoop) defaultConfig.getRunLoop()).getExecutorService(),
                        new TokenProvider.TokenChangeListener() {
                            @Override
                            public void onTokenChange() {
                                operationLogger.debug(
                                        "App check token changed, triggering app check token refresh");
                                refreshAppCheckToken();
                            }

                            @Override
                            public void onTokenChange(String token) {
                                operationLogger.debug(
                                        "App check token changed, triggering app check token refresh");
                                refreshAppCheckToken(token);
                            }
                        });

        // Open connection now so that by the time we are connected the deferred init has run
        // This relies on the fact that all callbacks run on repo's runloop.
        this.initialize();
    }

    // Connection.Delegate methods
    @Override
    public void onReady(long timestamp, String sessionId) {
        if (logger.logsDebug()) logger.debug("onReady");
        lastConnectionEstablishedTime = System.currentTimeMillis();
        handleTimestamp(timestamp);

        if (this.firstConnection) {
            sendConnectStats();
        }

        restoreTokens();
        this.firstConnection = false;
        this.lastSessionId = sessionId;
        for (Delegate delegate : listens)
            delegate.onConnect();
    }

    @Override
    public void onCacheHost(String host) {
        this.cachedHost = host;
    }

    private void initialize() {
        this.tryScheduleReconnect();
    }

    private void shutdown() {
        this.interrupt("shutdown");
    }

    @Override
    public void purgeOutstandingWrites() {
        for (OutstandingPut put : this.outstandingPuts.values()) {
            if (put.onComplete != null) {
                put.onComplete.onRequestResult("write_canceled", null);
            }
        }
        for (OutstandingDisconnect onDisconnect : this.onDisconnectRequestQueue) {
            if (onDisconnect.onComplete != null) {
                onDisconnect.onComplete.onRequestResult("write_canceled", null);
            }
        }
        this.outstandingPuts.clear();
        this.onDisconnectRequestQueue.clear();
        // Only if we are not connected can we reliably determine that we don't have onDisconnects
        // (outstanding) anymore. Otherwise we leave the flag untouched.
        if (!connected()) {
            this.hasOnDisconnects = false;
        }
        doIdleCheck();
    }

    @Override
    public void onDataMessage(Map<String, Object> message) {
        if (message.containsKey(REQUEST_NUMBER)) {
            // this is a response to a request we sent
            // TODO: this is a hack. Make the json parser give us a Long
            long rn = (Integer) message.get(REQUEST_NUMBER);
            ConnectionRequestCallback responseListener = requestCBHash.remove(rn);
            if (responseListener != null) {
                // jackson gives up Map<String, Object> for json objects
                @SuppressWarnings("unchecked")
                Map<String, Object> response = (Map<String, Object>) message.get(RESPONSE_FOR_REQUEST);
                responseListener.onResponse(response);
            }
        } else if (message.containsKey(REQUEST_ERROR)) {
            // TODO: log the error? probably shouldn't throw here...
        } else if (message.containsKey(SERVER_ASYNC_ACTION)) {
            String action = (String) message.get(SERVER_ASYNC_ACTION);
            // jackson gives up Map<String, Object> for json objects
            @SuppressWarnings("unchecked")
            Map<String, Object> body = (Map<String, Object>) message.get(SERVER_ASYNC_PAYLOAD);
            onDataPush(action, body);
        } else {
            if (logger.logsDebug()) logger.debug("Ignoring unknown message: " + message);
        }
    }

    @Override
    public void onDisconnect(Connection.DisconnectReason reason) {
        if (logger.logsDebug()) logger.debug("Got on disconnect due to " + reason.name());
        this.connectionState = ConnectionState.Disconnected;
        this.realtime = null;
        this.hasOnDisconnects = false;
        requestCBHash.clear();
        cancelSentTransactions();
        if (shouldReconnect()) {
            long timeSinceLastConnectSucceeded =
                    System.currentTimeMillis() - lastConnectionEstablishedTime;
            boolean lastConnectionWasSuccessful;
            if (lastConnectionEstablishedTime > 0) {
                lastConnectionWasSuccessful =
                        timeSinceLastConnectSucceeded > SUCCESSFUL_CONNECTION_ESTABLISHED_DELAY;
            } else {
                lastConnectionWasSuccessful = false;
            }
            if (reason == Connection.DisconnectReason.SERVER_RESET || lastConnectionWasSuccessful) {
                retryHelper.signalSuccess();
            }
            tryScheduleReconnect();
        }
        lastConnectionEstablishedTime = 0;
        for (Delegate delegate : listens)
            delegate.onDisconnect();
    }

    @Override
    public void onKill(String reason) {
        if (reason.equals(INVALID_APP_CHECK_TOKEN)
                && invalidAppCheckTokenCount < INVALID_TOKEN_THRESHOLD) {
            invalidAppCheckTokenCount++;
            logger.warn(
                    "Detected invalid AppCheck token. Reconnecting ("
                            + (INVALID_TOKEN_THRESHOLD - invalidAppCheckTokenCount)
                            + " attempts remaining)");
        } else {
            logger.warn(
                    "Firebase Database connection was forcefully killed by the server. Will not attempt"
                            + " reconnect. Reason: "
                            + reason);

            interrupt(SERVER_KILL_INTERRUPT_REASON);
        }
    }

    @Override
    public void unlisten(Delegate listener) {
        if (logger.logsDebug()) logger.debug("removing listener ");
        if (!listens.contains(listener)) {
            if (logger.logsDebug())
                logger.debug(
                        "Trying to remove listener but no listener exists.");
        } else {
            listens.remove(listener);
        }
        doIdleCheck();
    }

    @Override
    public void listen(Delegate listener) {
        if (logger.logsDebug()) logger.debug("adding listener ");
        if (listens.contains(listener)) {
            if (logger.logsDebug())
                logger.debug(
                        "Trying to add listener but listener already exists.");
        } else {
            listens.add(listener);
        }
        doIdleCheck();
    }

    private boolean connected() {
        return connectionState == ConnectionState.Authenticating
                || connectionState == ConnectionState.Connected;
    }

    private boolean canSendWrites() {
        return connectionState == ConnectionState.Connected;
    }

    private boolean canSendReads() {
        return connectionState == ConnectionState.Connected;
    }

    @Override
    public void onDisconnectMerge(
            List<String> path, Map<String, Object> updates, final RequestResultCallback onComplete) {
        // TODO : save listenes for when we are disconnected like here
        this.hasOnDisconnects = true;
        if (canSendWrites()) {
            sendOnDisconnect(REQUEST_ACTION_ONDISCONNECT_MERGE, updates, onComplete);
        } else {
            onDisconnectRequestQueue.add(
                    new OutstandingDisconnect(REQUEST_ACTION_ONDISCONNECT_MERGE, updates, onComplete));
        }
        doIdleCheck();
    }

    @Override
    public void onDisconnectCancel(List<String> path, RequestResultCallback onComplete) {
        // We do not mark hasOnDisconnects true here, because we only are removing disconnects.
        // However, we can also not reliably determine whether we had onDisconnects, so we can't
        // and do not reset the flag.
        if (canSendWrites()) {
            sendOnDisconnect(REQUEST_ACTION_ONDISCONNECT_CANCEL, null, onComplete);
        } else {
            onDisconnectRequestQueue.add(
                    new OutstandingDisconnect(REQUEST_ACTION_ONDISCONNECT_CANCEL, null, onComplete));
        }
        doIdleCheck();
    }

    public void interrupt(String reason) {
        if (logger.logsDebug()) logger.debug("Connection interrupted for: " + reason);
        interruptReasons.add(reason);

        if (realtime != null) {
            // Will call onDisconnect and set the connection state to Disconnected
            realtime.close();
            realtime = null;
        } else {
            retryHelper.cancel();
            this.connectionState = ConnectionState.Disconnected;
        }
        // Reset timeouts
        retryHelper.signalSuccess();
    }

    public void resume(String reason) {
        if (logger.logsDebug()) {
            logger.debug("Connection no longer interrupted for: " + reason);
        }

        interruptReasons.remove(reason);

        if (shouldReconnect() && connectionState == ConnectionState.Disconnected) {
            tryScheduleReconnect();
        }
    }

    public boolean isInterrupted(String reason) {
        return interruptReasons.contains(reason);
    }

    boolean shouldReconnect() {
        return interruptReasons.size() == 0;
    }

    @Override
    public void refreshAuthToken() {
        // Old versions of the database client library didn't have synchronous access to the
        // new token and call this instead of the overload that includes the new token.

        // After a refresh token any subsequent operations are expected to have the authentication
        // status at the point of this call. To avoid race conditions with delays after getToken,
        // we close the connection to make sure any writes/listens are queued until the connection
        // is reauthed with the current token after reconnecting. Note that this will trigger
        // onDisconnects which isn't ideal.
        logger.debug("Auth token refresh requested");

        // By using interrupt instead of closing the connection we make sure there are no race
        // conditions with other fetch token attempts (interrupt/resume is expected to handle those
        // correctly)
        interrupt(TOKEN_REFRESH_INTERRUPT_REASON);
        resume(TOKEN_REFRESH_INTERRUPT_REASON);
    }

    @Override
    public void refreshAuthToken(String token) {
        logger.debug("Auth token refreshed.");
        this.authToken = token;
        if (connected()) {
            if (token != null) {
                upgradeAuth();
            } else {
                sendUnauth();
            }
        }
    }

    @Override
    public void refreshAppCheckToken() {
        logger.debug("App check token refresh requested");

        // By using interrupt instead of closing the connection we make sure there are no race
        // conditions with other fetch token attempts (interrupt/resume is expected to handle those
        // correctly)
        interrupt(TOKEN_REFRESH_INTERRUPT_REASON);
        resume(TOKEN_REFRESH_INTERRUPT_REASON);
    }

    @Override
    public void refreshAppCheckToken(String token) {
        logger.debug("App check token refreshed.");
        this.appCheckToken = token;
        if (connected()) {
            if (token != null) {
                upgradeAppCheck();
            } else {
                sendUnAppCheck();
            }
        }
    }

    private void tryScheduleReconnect() {
        if (shouldReconnect()) {
            hardAssert(
                    this.connectionState == ConnectionState.Disconnected,
                    "Not in disconnected state: %s",
                    this.connectionState);
            final boolean forceAuthTokenRefresh = this.forceAuthTokenRefresh;
            final boolean forceAppCheckTokenRefresh = this.forceAppCheckTokenRefresh;
            logger.debug("Scheduling connection attempt");
            this.forceAuthTokenRefresh = false;
            this.forceAppCheckTokenRefresh = false;
            retryHelper.retry(
                    () -> {
                        hardAssert(
                                connectionState == ConnectionState.Disconnected,
                                "Not in disconnected state: %s",
                                connectionState);
                        connectionState = ConnectionState.GettingToken;
                        currentGetTokenAttempt++;
                        final long thisGetTokenAttempt = currentGetTokenAttempt;

                        Task<String> authToken = fetchAuthToken(forceAuthTokenRefresh);
                        Task<String> appCheckToken = fetchAppCheckToken(forceAppCheckTokenRefresh);

                        Task.whenAll(authToken, appCheckToken)
                                .addOnSuccessListener(
                                        executorService,
                                        aVoid -> {
                                            if (thisGetTokenAttempt == currentGetTokenAttempt) {
                                                if (connectionState == ConnectionState.GettingToken) {
                                                    logger.debug("Successfully fetched token, opening connection");
                                                    openNetworkConnection(authToken.getResult(), appCheckToken.getResult());
                                                } else if (connectionState == ConnectionState.Disconnected) {
                                                    logger.debug(
                                                            "Not opening connection after token refresh, "
                                                                    + "because connection was set to disconnected");
                                                }
                                            } else {
                                                logger.debug(
                                                        "Ignoring getToken result, because this was not the "
                                                                + "latest attempt.");
                                            }
                                        })
                                .addOnFailureListener(
                                        executorService,
                                        error -> {
                                            if (thisGetTokenAttempt == currentGetTokenAttempt) {
                                                connectionState = ConnectionState.Disconnected;
                                                logger.debug("Error fetching token: " + error);
                                                tryScheduleReconnect();
                                            } else {
                                                logger.debug(
                                                        "Ignoring getToken error, because this was not the "
                                                                + "latest attempt.");
                                            }
                                        });
                    });
        }
    }

    private Task<String> fetchAuthToken(boolean forceAuthTokenRefresh) {
        TaskCompletionSource<String> taskCompletionSource = new TaskCompletionSource<>();
        logger.debug("Trying to fetch auth token");
        authTokenProvider.getToken(
                forceAuthTokenRefresh,
                new ConnectionTokenProvider.GetTokenCallback() {
                    @Override
                    public void onSuccess(String token) {
                        taskCompletionSource.setResult(token);
                    }

                    @Override
                    public void onError(String error) {
                        taskCompletionSource.setException(new Exception(error));
                    }
                });

        taskCompletionSource.getTask().addOnCompleteListener((task, result, exception) -> {
            logger.debug("Task is addOnCompleteListener");
        });
        return taskCompletionSource.getTask();
    }

    private Task<String> fetchAppCheckToken(boolean forceAppCheckTokenRefresh) {
        TaskCompletionSource<String> taskCompletionSource = new TaskCompletionSource<>();
        logger.debug("Trying to fetch app check token");

        appCheckTokenProvider.getToken(
                forceAppCheckTokenRefresh,
                new ConnectionTokenProvider.GetTokenCallback() {
                    @Override
                    public void onSuccess(String token) {
                        taskCompletionSource.setResult(token);
                    }

                    @Override
                    public void onError(String error) {
                        taskCompletionSource.setException(new Exception(error));
                    }
                });
        return taskCompletionSource.getTask();
    }

    private void openNetworkConnection(String authToken, String appCheckToken) {
        hardAssert(
                this.connectionState == ConnectionState.GettingToken,
                "Trying to open network connection while in the wrong state: %s",
                this.connectionState);
        // User might have logged out. Positive auth status is handled after authenticating with
        // the server
        if (authToken == null) {
            for (Delegate delegate : listens)
                delegate.onConnectionStatus(false);
        }
        this.authToken = authToken;
        this.appCheckToken = appCheckToken;
        this.connectionState = ConnectionState.Connecting;
        realtime =
                new Connection(
                        this.context, this.hostInfo, this.cachedHost, this, this.lastSessionId, appCheckToken);
        realtime.open();
    }

    private void sendOnDisconnect(
            String action, Object data, final RequestResultCallback onComplete) {
        Map<String, Object> request = new HashMap<>();
        request.put(REQUEST_DATA_PAYLOAD, data);

        if (logger.logsDebug()) logger.debug("onDisconnect " + action + " " + request);
        sendAction(
                action,
                request,
                response -> {
                    String status = (String) response.get(REQUEST_STATUS);
                    String errorMessage = null;
                    String errorCode = null;
                    if (!status.equals("ok")) {
                        errorCode = status;
                        errorMessage = (String) response.get(SERVER_DATA_UPDATE_BODY);
                    }
                    if (onComplete != null) {
                        onComplete.onRequestResult(errorCode, errorMessage);
                    }
                });
    }

    private void cancelSentTransactions() {
        List<OutstandingPut> cancelledTransactionWrites = new ArrayList<>();

        Iterator<Map.Entry<Long, OutstandingPut>> iter = outstandingPuts.entrySet().iterator();
        while (iter.hasNext()) {
            Map.Entry<Long, OutstandingPut> entry = iter.next();
            OutstandingPut put = entry.getValue();
            if (put.getRequest().containsKey(REQUEST_DATA_HASH) && put.wasSent()) {
                cancelledTransactionWrites.add(put);
                iter.remove();
            }
        }

        for (OutstandingPut put : cancelledTransactionWrites) {
            // onRequestResult() may invoke rerunTransactions() and enqueue new writes. We defer
            // calling it until we've finished enumerating all existing writes.
            put.getOnComplete().onRequestResult("disconnected", null);
        }
    }

    private void onDataPush(String action, Map<String, Object> body) {
        if (logger.logsDebug()) logger.debug("handleServerMessage: " + action + " " + body);
        if (action.equals(SERVER_ASYNC_DATA_UPDATE) || action.equals(SERVER_ASYNC_DATA_MERGE)) {
            boolean isMerge = action.equals(SERVER_ASYNC_DATA_MERGE);

            Object payloadData = body.get(SERVER_DATA_UPDATE_BODY);
            Long tagNumber = ConnectionUtils.longFromObject(body.get(SERVER_DATA_TAG));
            // ignore empty merges
            if (isMerge && (payloadData instanceof Map) && ((Map<?, ?>) payloadData).size() == 0) {
                if (logger.logsDebug()) logger.debug("ignoring empty merge for path ");
            } else {
                for (Delegate delegate : listens) {
                    delegate.onDataUpdate(payloadData, isMerge, tagNumber);
                }
            }
        } else if (action.equals(SERVER_ASYNC_AUTH_REVOKED)) {
            String status = (String) body.get(REQUEST_STATUS);
            String reason = (String) body.get(SERVER_DATA_UPDATE_BODY);
            onAuthRevoked(status, reason);
        } else if (action.equals(SERVER_ASYNC_APP_CHECK_REVOKED)) {
            String status = (String) body.get(REQUEST_STATUS);
            String reason = (String) body.get(SERVER_DATA_UPDATE_BODY);
            onAppCheckRevoked(status, reason);
        } else if (action.equals(SERVER_ASYNC_SECURITY_DEBUG)) {
            onSecurityDebugPacket(body);
        } else {
            if (logger.logsDebug()) logger.debug("Unrecognized action from server: " + action);
        }
    }

    private void onAuthRevoked(String errorCode, String errorMessage) {
        // This might be for an earlier token than we just recently sent. But since we need to close
        // the connection anyways, we can set it to null here and we will refresh the token later
        // on reconnect.
        logger.debug("Auth token revoked: " + errorCode + " (" + errorMessage + ")");
        this.authToken = null;
        this.forceAuthTokenRefresh = true;
        for (Delegate delegate : listens)
            delegate.onConnectionStatus(false);
        // Close connection and reconnect
        this.realtime.close();
    }

    private void onAppCheckRevoked(String errorCode, String errorMessage) {
        logger.debug("App check token revoked: " + errorCode + " (" + errorMessage + ")");
        this.appCheckToken = null;
        this.forceAppCheckTokenRefresh = true;
    }

    private void onSecurityDebugPacket(Map<String, Object> message) {
        // TODO: implement on iOS too
        logger.info((String) message.get("msg"));
    }

    private void upgradeAuth() {
        sendAuthHelper(/*restoreStateAfterComplete=*/ false);
    }

    private void upgradeAppCheck() {
        sendAppCheckTokenHelper(/*restoreStateAfterComplete=*/ false);
    }

    private void sendAuthAndRestoreState() {
        sendAuthHelper(/*restoreStateAfterComplete=*/ true);
    }

    private void sendAuthHelper(final boolean restoreStateAfterComplete) {
        hardAssert(connected(), "Must be connected to send auth, but was: %s", this.connectionState);
        if (logger.logsDebug()) logger.debug("Sending auth.");

        ConnectionRequestCallback onComplete =
                response -> {
                    String status = (String) response.get(REQUEST_STATUS);
                    if (status.equals("ok")) {
                        connectionState = ConnectionState.Connected;
                        invalidAuthTokenCount = 0;
                        sendAppCheckTokenHelper(restoreStateAfterComplete);
                    } else {
                        authToken = null;
                        forceAuthTokenRefresh = true;
                        for (Delegate delegate : listens)
                            delegate.onConnectionStatus(false);
                        String reason = (String) response.get(SERVER_RESPONSE_DATA);
                        logger.debug("Authentication failed: " + status + " (" + reason + ")");
                        realtime.close();

                        if (status.equals("invalid_token")) {
                            // We'll wait a couple times before logging the warning / increasing the
                            // retry period since oauth tokens will report as "invalid" if they're
                            // just expired. Plus there may be transient issues that resolve themselves.
                            invalidAuthTokenCount++;
                            if (invalidAuthTokenCount >= INVALID_TOKEN_THRESHOLD) {
                                // Set a long reconnect delay because recovery is unlikely.
                                retryHelper.setMaxDelay();
                                logger.warn(
                                        "Provided authentication credentials are invalid. This "
                                                + "usually indicates your FirebaseApp instance was not initialized "
                                                + "correctly. Make sure your google-services.json file has the "
                                                + "correct firebase_url and api_key. You can re-download "
                                                + "google-services.json from "
                                                + "https://console.firebase.google.com/.");
                            }
                        }
                    }
                };

        Map<String, Object> request = new HashMap<String, Object>();
        GAuthToken gAuthToken = GAuthToken.tryParseFromString(this.authToken);
        if (gAuthToken != null) {
            request.put(REQUEST_CREDENTIAL, gAuthToken.getToken());
            if (gAuthToken.getAuth() != null) {
                request.put(REQUEST_AUTHVAR, gAuthToken.getAuth());
            }
            sendSensitive(REQUEST_ACTION_GAUTH, /*isSensitive=*/ true, request, onComplete);
        } else {
            request.put(REQUEST_CREDENTIAL, authToken);
            sendSensitive(REQUEST_ACTION_AUTH, /*isSensitive=*/ true, request, onComplete);
        }
    }

    private void sendAppCheckTokenHelper(final boolean restoreStateAfterComplete) {
        if (appCheckToken == null) {
            restoreState();
            return;
        }

        hardAssert(connected(), "Must be connected to send auth, but was: %s", this.connectionState);
        if (logger.logsDebug()) logger.debug("Sending app check.");

        ConnectionRequestCallback onComplete =
                response -> {
                    String status = (String) response.get(REQUEST_STATUS);
                    if (status.equals("ok")) {
                        invalidAppCheckTokenCount = 0;
                    } else {
                        appCheckToken = null;
                        forceAppCheckTokenRefresh = true;
                        String reason = (String) response.get(SERVER_RESPONSE_DATA);
                        logger.debug("App check failed: " + status + " (" + reason + ")");
                        // Note: We don't close the connection as the developer may not have
                        // enforcement enabled. The backend closes connections with enforcements.
                    }

                    if (restoreStateAfterComplete) {
                        restoreState();
                    }
                };

        Map<String, Object> request = new HashMap<>();
        hardAssert(appCheckToken != null, "App check token must be set!");
        request.put(REQUEST_APPCHECK_TOKEN, appCheckToken);
        sendSensitive(REQUEST_ACTION_APPCHECK, /*isSensitive=*/ true, request, onComplete);
    }

    private void sendUnauth() {
        hardAssert(connected(), "Must be connected to send unauth.");
        hardAssert(authToken == null, "Auth token must not be set.");
        sendAction(REQUEST_ACTION_UNAUTH, Collections.emptyMap(), null);
    }

    private void sendUnAppCheck() {
        hardAssert(connected(), "Must be connected to send unauth.");
        hardAssert(appCheckToken == null, "App check token must not be set.");
        sendAction(REQUEST_ACTION_UNAPPCHECK, Collections.emptyMap(), null);
    }

    private void restoreTokens() {
        if (logger.logsDebug()) logger.debug("calling restore tokens");

        hardAssert(
                this.connectionState == ConnectionState.Connecting,
                "Wanted to restore tokens, but was in wrong state: %s",
                this.connectionState);

        if (authToken != null) {
            if (logger.logsDebug()) logger.debug("Restoring auth.");
            this.connectionState = ConnectionState.Authenticating;
            sendAuthAndRestoreState();
        } else {
            if (logger.logsDebug()) logger.debug("Not restoring auth because auth token is null.");
            this.connectionState = ConnectionState.Connected;
            // Send our appcheck token (if we have one), then restore state.
            sendAppCheckTokenHelper(true);
        }
    }

    private void restoreState() {
        hardAssert(
                this.connectionState == ConnectionState.Connected,
                "Should be connected if we're restoring state, but we are: %s",
                this.connectionState);

        if (logger.logsDebug()) logger.debug("Restoring writes.");

        // Restore disconnect operations
        for (OutstandingDisconnect disconnect : onDisconnectRequestQueue) {
            sendOnDisconnect(
                    disconnect.getAction(),
                    disconnect.getData(),
                    disconnect.getOnComplete());
        }
        onDisconnectRequestQueue.clear();
    }

    private void handleTimestamp(long timestamp) {
        if (logger.logsDebug()) logger.debug("handling timestamp");
        long timestampDelta = timestamp - System.currentTimeMillis();
        Map<String, Object> updates = new HashMap<String, Object>();
        updates.put(DOT_INFO_SERVERTIME_OFFSET, timestampDelta);
        for (Delegate delegate : listens)
            delegate.onServerInfoUpdate(updates);
    }

    private void sendData(Object newValueUnresolved,
                          final CompletionListener onComplete) {
        Map<String, Object> request = new HashMap<String, Object>();
        // Only bother to send query if it's non-default
        request.put(REQUEST_DATA_PAYLOAD, newValueUnresolved);

        sendAction(
                REQUEST_ACTION_QUERY,
                request,
                response -> {
                    String status = (String) response.get(REQUEST_STATUS);
                    // log warnings in any case, even if listener was already removed

                    // only trigger actions if the listen hasn't been removed (and maybe readded)
                    if (onComplete != null) {
                        if (!status.equals("ok")) {
                            String errorMessage = (String) response.get(SERVER_DATA_UPDATE_BODY);
                            onComplete.onComplete(NetworkError.fromStatus(status, errorMessage));
                        } else {
                            onComplete.onComplete(null);
                        }
                    }
                });
    }

    private void sendStats(final Map<String, Integer> stats) {
        if (!stats.isEmpty()) {
            Map<String, Object> request = new HashMap<String, Object>();
            request.put(REQUEST_COUNTERS, stats);
            sendAction(
                    REQUEST_ACTION_STATS,
                    request,
                    response -> {
                        String status = (String) response.get(REQUEST_STATUS);
                        if (!status.equals("ok")) {
                            String errorMessage = (String) response.get(SERVER_DATA_UPDATE_BODY);
                            if (logger.logsDebug()) {
                                logger.debug(
                                        "Failed to send stats: " + status + " (message: " + errorMessage + ")");
                            }
                        }
                    });
        } else {
            if (logger.logsDebug()) logger.debug("Not sending stats because stats are empty");
        }
    }

    private void sendConnectStats() {
        Map<String, Integer> stats = new HashMap<>();
        if (this.context.isPersistenceEnabled()) {
            stats.put("persistence.android.enabled", 1);
        }
        stats.put("sdk.android." + context.getClientSdkVersion().replace('.', '-'), 1);
        // TODO: Also send stats for connection version
        if (logger.logsDebug()) logger.debug("Sending first connection stats");
        sendStats(stats);
    }

    private void sendAction(
            String action, Map<String, Object> message, ConnectionRequestCallback onResponse) {
        sendSensitive(action, /*isSensitive=*/ false, message, onResponse);
    }

    private void sendSensitive(
            String action,
            boolean isSensitive,
            Map<String, Object> message,
            ConnectionRequestCallback onResponse) {
        long rn = nextRequestNumber();
        Map<String, Object> request = new HashMap<String, Object>();
        request.put(REQUEST_NUMBER, rn);
        request.put(REQUEST_ACTION, action);
        request.put(REQUEST_PAYLOAD, message);
        realtime.sendRequest(request, isSensitive);
        requestCBHash.put(rn, onResponse);
    }

    private long nextRequestNumber() {
        return requestCounter++;
    }

    private void doIdleCheck() {
        if (isIdle()) {
            if (this.inactivityTimer != null) {
                this.inactivityTimer.cancel(false);
            }

            this.inactivityTimer =
                    this.executorService.schedule(
                            () -> {
                                inactivityTimer = null;
                                if (idleHasTimedOut()) {
                                    interrupt(IDLE_INTERRUPT_REASON);
                                } else {
                                    doIdleCheck();
                                }
                            },
                            IDLE_TIMEOUT,
                            TimeUnit.MILLISECONDS);
        } else if (isInterrupted(IDLE_INTERRUPT_REASON)) {
            hardAssert(!isIdle());
            this.resume(IDLE_INTERRUPT_REASON);
        }
    }

    /**
     * @return Returns true if the connection is currently not being used (for listen, outstanding
     * operations).
     */
    private boolean isIdle() {
        return this.listens.isEmpty()
                && this.outstandingGets.isEmpty()
                && this.requestCBHash.isEmpty()
                && !this.hasOnDisconnects;
    }

    private boolean idleHasTimedOut() {
        long now = System.currentTimeMillis();
        return isIdle() && now > (this.lastWriteTimestamp + IDLE_TIMEOUT);
    }

    /**
     * Set the data at this location to the given value. Passing null to setValue() will delete the
     * data at the specified location. The native types accepted by this method for the value
     * correspond to the JSON types:
     *
     * <ul>
     *   <li><code>Boolean</code>
     *   <li><code>Long</code>
     *   <li><code>Double</code>
     *   <li><code>String</code>
     *   <li><code>Map&lt;String, Object&gt;</code>
     *   <li><code>List&lt;Object&gt;</code>
     * </ul>
     *
     * <br>
     * <br>
     * In addition, you can set instances of your own class into this location, provided they satisfy
     * the following constraints:
     *
     * <ol>
     *   <li>The class must have a default constructor that takes no arguments
     *   <li>The class must define public getters for the properties to be assigned. Properties
     *       without a public getter will be set to their default value when an instance is
     *       deserialized
     * </ol>
     *
     * <br>
     * <br>
     * Generic collections of objects that satisfy the above constraints are also permitted, i.e.
     * <code>Map&lt;String, MyPOJO&gt;</code>, as well as null values.
     *
     * @param value The value to set at this location or null to delete the existing data
     * @return The {@link Task} for this operation.
     */
    @NotNull
    public Task<Void> sendValue(@Nullable Object value) {
        return sendValueInternal(value, null);
    }

    /**
     * Set the data at this location to the given value. Passing null to setValue() will delete the
     * data at the specified location. The native types accepted by this method for the value
     * correspond to the JSON types:
     *
     * <ul>
     *   <li><code>Boolean</code>
     *   <li><code>Long</code>
     *   <li><code>Double</code>
     *   <li><code>String</code>
     *   <li><code>Map&lt;String, Object&gt;</code>
     *   <li><code>List&lt;Object&gt;</code>
     * </ul>
     *
     * <br>
     * <br>
     * In addition, you can set instances of your own class into this location, provided they satisfy
     * the following constraints:
     *
     * <ol>
     *   <li>The class must have a default constructor that takes no arguments
     *   <li>The class must define public getters for the properties to be assigned. Properties
     *       without a public getter will be set to their default value when an instance is
     *       deserialized
     * </ol>
     *
     * <br>
     * <br>
     * Generic collections of objects that satisfy the above constraints are also permitted, i.e.
     * <code>Map&lt;String, MyPOJO&gt;</code>, as well as null values.
     *
     * @param value    The value to set at this location or null to delete the existing data
     * @param listener A listener that will be triggered with the results of the operation
     */
    public void sendValue(@Nullable Object value, @Nullable CompletionListener listener) {
        sendValueInternal(value, listener);
    }

    private Task<Void> sendValueInternal(Object value, CompletionListener optListener) {
        Object bouncedValue = CustomClassMapper.convertToPlainJavaTypes(value);
        Validation.validateWritableObject(bouncedValue);
        final Pair<Task<Void>, CompletionListener> wrapped = Utilities.wrapOnComplete(optListener);
        executorService.schedule(() -> sendData(bouncedValue, wrapped.getSecond()), 10000, TimeUnit.MILLISECONDS);
        return wrapped.getFirst();
    }

    /**
     * Resumes our connection to the Firebase Database backend after a previous {@link #goOffline()}
     * call.
     */
    public void goOnline() {
        scheduleNow(() -> this.interrupt(USER_REQUEST_INTERRUPT_REASON));
    }

    /**
     * Shuts down our connection to the Firebase Database backend until {@link #goOnline()} is called.
     */
    public void goOffline() {
        scheduleNow(() -> this.resume(USER_REQUEST_INTERRUPT_REASON));
    }


    // Regarding the next three methods: scheduleNow, schedule, and postEvent:
    // Please use these methods rather than accessing the context directly. This ensures that the
    // context is correctly re-initialized if it was previously shut down. In practice, this means
    // that when a task is submitted, we will guarantee at least one thread in the core pool for the
    // run loop.

    protected void scheduleNow(Runnable r) {
        defaultConfig.requireStarted();
        defaultConfig.getRunLoop().scheduleNow(r);
    }

    protected void scheduleDelayed(Runnable r, long millis) {
        defaultConfig.requireStarted();
        defaultConfig.getRunLoop().schedule(r, millis);
    }

    protected void postEvent(Runnable r) {
        defaultConfig.requireStarted();
        defaultConfig.getEventTarget().postEvent(r);
    }

    // For testing
    public void injectConnectionFailure() {
        if (this.realtime != null) {
            this.realtime.injectConnectionFailure();
        }
    }
}