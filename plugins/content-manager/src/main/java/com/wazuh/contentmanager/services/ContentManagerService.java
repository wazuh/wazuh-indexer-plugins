package com.wazuh.contentmanager.services;

import com.wazuh.contentmanager.model.rest.SubscriptionModel;
import org.opensearch.threadpool.ThreadPool;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Service to manage CTI subscription operations and handle update rate-limiting.
 * Delegates subscription storage to the SubscriptionModel singleton.
 */
public class ContentManagerService {
    private final ThreadPool threadPool;

    // simple rate limiting: allow 2 requests per hour
    public static final int RATE_LIMIT = 200;
    private AtomicInteger used = new AtomicInteger(0);
    private long windowReset = Instant.now().getEpochSecond() + 3600;

    public ContentManagerService(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    public synchronized boolean canTriggerUpdate() {
        long now = Instant.now().getEpochSecond();
        if (now >= windowReset) {
            used.set(0);
            windowReset = now + 3600;
        }
        if (used.get() >= RATE_LIMIT) return false;
        used.incrementAndGet();
        return true;
    }

    public long getRateLimitReset() { return windowReset; }

    /**
     * Retrieves the current subscription from the SubscriptionModel singleton.
     *
     * @return The current subscription, or null if no subscription exists
     */
    public SubscriptionModel getSubscription() {
        return SubscriptionModel.getInstance();
    }

    /**
     * Deletes the current subscription from the SubscriptionModel singleton.
     */
    public void deleteSubscription() {
        SubscriptionModel.deleteInstance();
    }
}
