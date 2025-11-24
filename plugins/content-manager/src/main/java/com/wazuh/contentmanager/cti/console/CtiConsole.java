package com.wazuh.contentmanager.cti.console;

import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.console.service.AuthService;
import com.wazuh.contentmanager.cti.console.service.PlansService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.util.concurrent.FutureUtils;

import java.util.concurrent.*;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

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
     * Lock for synchronizing token retrieval.
     */
    private final Lock tokenLock = new ReentrantLock();

    /**
     * Condition to signal when token is obtained.
     */
    private final Condition tokenAvailable = tokenLock.newCondition();

    /**
     * Thread executor.
     */
    private final ScheduledExecutorService executor;

    /**
     * Default constructor.
     */
    public CtiConsole() {
        this.executor = Executors.newSingleThreadScheduledExecutor(r -> new Thread(r, TASK_NAME));
    }

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
        tokenLock.lock();
        try {
            this.token = t;
            log.info("Permanent token changed: {}", this.token); // TODO do not log the token

            // Cancel polling
            FutureUtils.cancel(this.getTokenTaskFuture);
            this.executor.shutdown();

            // Signal all waiting threads that the token has been obtained
            tokenAvailable.signalAll();
        } finally {
            tokenLock.unlock();
        }
    }

    /**
     * Starts a periodic task to obtain a permanent token from the CTI Console.
     * @param interval the period between successive executions.
     */
    private void getToken(int interval/* TODO sub details */) {
        Runnable getTokenTask = () -> this.authService.getToken("client_id", "polling");
        this.getTokenTaskFuture = this.executor.scheduleAtFixedRate(getTokenTask, interval, interval, TimeUnit.SECONDS);
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

    /**
     * Waits for the token to be obtained from the CTI Console with a timeout.
     * This method blocks the calling thread until either:
     * - A token is successfully obtained (returns the token)
     * - The timeout expires (returns null)
     * - The thread is interrupted (throws InterruptedException)
     *
     * @param timeoutMillis maximum time to wait in milliseconds.
     * @return the obtained token, or null if timeout expires or token is not obtained.
     * @throws InterruptedException if the waiting thread is interrupted.
     */
    public Token waitForToken(long timeoutMillis) throws InterruptedException {
        tokenLock.lock();
        try {
            long remainingNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis);

            // Wait until token is obtained or timeout expires
            while (this.token == null && remainingNanos > 0) {
                remainingNanos = tokenAvailable.awaitNanos(remainingNanos);
            }

            return this.token;
        } finally {
            tokenLock.unlock();
        }
    }

    /**
     * Waits indefinitely for the token to be obtained from the CTI Console.
     * This method blocks the calling thread until a token is successfully obtained or interrupted.
     *
     * @return the obtained token.
     * @throws InterruptedException if the waiting thread is interrupted.
     */
    public Token waitForToken() throws InterruptedException {
        tokenLock.lock();
        try {
            while (this.token == null) {
                tokenAvailable.await();
            }
            return this.token;
        } finally {
            tokenLock.unlock();
        }
    }
}
