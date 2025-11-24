package com.wazuh.contentmanager.cti.console;

import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.console.service.AuthService;
import com.wazuh.contentmanager.cti.console.service.PlansService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.util.concurrent.FutureUtils;

import java.util.concurrent.*;

/**
 * CTI Console main class. Contains and manages CTI Console internal state and services.
 */
public class CtiConsole implements TokenListener {
    private static final Logger log = LogManager.getLogger(CtiConsole.class);
    private static final String TASK_NAME = "CTI Console Periodic Task";

    /**
     * CTI Console authentication service.
     */
    private AuthService authService;

    /**
     * CTI Console plans service.
     */
    private PlansService plansService;

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
     */
    public CtiConsole() { }

    /**
     * Sets the plan service for this CTI Console instance.
     * @param plansService plans service implementation.
     */
    public void setPlansService(PlansService plansService) {
        // Gracefully close existing http client
        if (this.plansService != null) {
            this.plansService.close();
        }
        this.plansService = plansService;
    }

    /**
     * Sets the authentication service for this CTI Console instance.
     * @param authService authentication service implementation.
     */
    public void setAuthService(AuthService authService) {
        // Gracefully close existing http client
        if (this.authService != null) {
            this.authService.close();
        }
        this.authService = authService;

        // Pass the instance as a listener for token changes.
        this.authService.addListener(this);
    }

    @Override
    public void onTokenChanged(Token t) {
        this.token = t;
        log.info("Permanent token changed: {}", this.token); // TODO do not log the token

        // Cancel polling
        FutureUtils.cancel(this.getTokenTaskFuture);
    }

    /**
     * Starts a periodic task to obtain a permanent token from the CTI Console.
     * @param interval the period between successive executions.
     */
    private void getToken(int interval/* TODO sub details */) {
        ScheduledExecutorService executor  = Executors.newSingleThreadScheduledExecutor(r -> new Thread(r, TASK_NAME));
        Runnable getTokenTask = () -> this.authService.getToken("client_id", "polling");
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
