package com.wazuh.contentmanager.rest;

import org.opensearch.threadpool.ThreadPool;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Minimal in-memory service to manage a single CTI subscription and handle update rate-limiting.
 */
public class ContentManagerService {
    private final ThreadPool threadPool;
    private final Map<String, Subscription> subscriptionStore = new ConcurrentHashMap<>();

    // simple rate limiting: allow 2 requests per hour
    private final int RATE_LIMIT = 2;
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

    public void saveSubscription(Subscription s) {
        subscriptionStore.put("default", s);
    }

    public Subscription getSubscription() {
        return subscriptionStore.get("default");
    }

    public void deleteSubscription() {
        subscriptionStore.remove("default");
    }

    public static class Subscription {
        public final String deviceCode;
        public final String clientId;
        public final int expiresIn;
        public final int interval;

        public Subscription(String deviceCode, String clientId, int expiresIn, int interval) {
            this.deviceCode = deviceCode;
            this.clientId = clientId;
            this.expiresIn = expiresIn;
            this.interval = interval;
        }
    }
}
