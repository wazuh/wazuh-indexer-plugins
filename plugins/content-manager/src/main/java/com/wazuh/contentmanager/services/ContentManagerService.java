package com.wazuh.contentmanager.services;

import com.wazuh.contentmanager.model.rest.Subscription;
import com.wazuh.contentmanager.model.rest.Token;
import org.opensearch.threadpool.ThreadPool;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Service to manage CTI subscription operations and handle update rate-limiting.
 * Delegates subscription storage to the Subscription class.
 */
public class ContentManagerService {
    private final ThreadPool threadPool;

    // Stored subscription instance 
    private Subscription subscription;
    // Stored token instance
    private Token token;

    // Rate limiting:  allow 2 requests per hour
    public static final int RATE_LIMIT = 2;
    private AtomicInteger used = new AtomicInteger(0);
    private long windowReset = Instant.now().getEpochSecond() + 3600;

    public ContentManagerService(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    public synchronized boolean canTriggerUpdate() {
        return canTriggerUpdate(null);
    }

    /**
     * Allows callers (tests) to provide an override rate limit for this invocation.
     * If overrideLimit is null the configured/default limit is used.
     */
    public synchronized boolean canTriggerUpdate(Integer overrideLimit) {
        int effectiveLimit = (overrideLimit != null && overrideLimit > 0) ? overrideLimit : getRateLimit();
        long now = Instant.now().getEpochSecond();
        if (now >= windowReset) {
            used.set(0);
            windowReset = now + 3600;
        }
        if (used.get() >= effectiveLimit) return false;
        used.incrementAndGet();
        return true;
    }

    public long getRateLimitReset() { return windowReset; }

    /**
     * Resets the rate limit counter. This method is primarily intended for testing purposes
     * to ensure tests start with a clean state.
     */
    public synchronized void resetRateLimit() {
        used.set(0);
        windowReset = Instant.now().getEpochSecond() + 3600;
    }

    /**
     * Returns the effective rate limit used by the service. Reads the system property
     * `content.manager.rate_limit` if present, otherwise falls back to the default.
     */
    public static int getRateLimit() {
        String prop = System.getProperty("content.manager.rate_limit");
        if (prop != null) {
            try {
                int v = Integer.parseInt(prop);
                if (v > 0) return v;
            } catch (NumberFormatException ignored) { }
        }
        return RATE_LIMIT;
    }

    /**
     * Retrieves the current subscription from the Subscription class.
     *
     * @return The current subscription, or null if no subscription exists
     */
    public Subscription getSubscription() {
        return subscription;
    }

    /**
     * Deletes the current subscription from the Subscription class.
     * Also resets the rate limit counter to ensure tests start with a clean state.
     */
    public void deleteSubscription() {
        this.subscription = null;
        resetRateLimit();
    }

    /**
     * Creates or updates the stored subscription instance.
     */
    public void setSubscription(String deviceCode, String clientId, int expiresIn, int interval) {
        this.subscription = new Subscription(deviceCode, clientId, expiresIn, interval);
    }

    public Token getToken() {
        return token;
    }

    public void setToken(String accessToken, String tokenType) {
        this.token = new Token(accessToken, tokenType);
    }
}
