package com.wazuh.contentmanager.cti.console;

import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.console.service.AuthService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * CTI Console main class. Contains and manages CTI Console internal state and services.
 */
public class CtiConsole implements TokenListener {
    private static final Logger log = LogManager.getLogger(CtiConsole.class);

    /**
     * CTI Console authentication service.
     */
    private final AuthService authService;

    /**
     * Permanent token of this instance to authenticate to the CTI Console.
     */
    private Token token;

    /**
     * Used to cancel the periodic task to obtain a token when completed or expired.
     */
    private ScheduledFuture<?> getTokenTaskFuture;

    /**
     * Default constructor.
     * @param authService authentication service implementation.
     */
    public CtiConsole(AuthService authService) {
        this.authService = authService;
        this.token = null;

        // Pass the instance as a listener for token changes.
        this.authService.addListener(this);
    }

    @Override
    public void onTokenChanged(Token t) {
        this.token = t;
        log.info("Permanent token changed: {}", this.token);

        // Cancel polling
        this.getTokenTaskFuture.cancel(true);
    }

    /**
     * Starts a periodic task to obtain a permanent token from the CTI Console.
     * @param interval the period between successive executions.
     */
    private void getToken(int interval/* TODO sub details */) {
        ScheduledExecutorService executor  = Executors.newSingleThreadScheduledExecutor();
        Runnable getTokenTask = () -> this.authService.getToken("client_id", "polling");;
        this.getTokenTaskFuture = executor.scheduleAtFixedRate(getTokenTask, interval, interval, TimeUnit.SECONDS);
    }

    /**
     * Triggers the mechanism to obtain a permanent token from the CTI Console.
     * This method is meant to be called by the Rest handler.
     */
    public void onPostSubscriptionRequest (/* TODO sub details */) {
        this.getToken(5);
    }

    /**
     * CTI Console token getter.
     * @return permanent token.
     */
    public Token getToken() {
        return this.token;
    }

    /**
     * Returns whether the periodic task to obtain a token has finished. See {@link ScheduledFuture#isDone()}.
     * @return true if the task is done, false otherwise.
     */
    public boolean isTokenTaskCompleted() {
        return this.getTokenTaskFuture.isDone();
    }
}
