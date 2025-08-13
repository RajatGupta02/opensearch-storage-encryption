/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.iv;

import java.security.Key;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * TTL-based cache for data keys with automatic expiration and optional size limits.
 * Provides thread-safe caching of decrypted data keys with configurable time-to-live.
 *
 * @opensearch.internal
 */
public class DataKeyCache {

    private static final Logger LOGGER = LogManager.getLogger(DataKeyCache.class);

    private final ConcurrentHashMap<String, CacheEntry> cache;
    private final long ttlMillis;
    private final int maxSize;
    private final ScheduledExecutorService cleanupExecutor;
    private final ReentrantReadWriteLock refreshLock;

    /**
     * Represents a cached data key entry with expiration metadata.
     */
    private static class CacheEntry {
        final Key dataKey;
        final long expirationTime;
        final String keyId;
        volatile long lastAccessTime;

        CacheEntry(Key dataKey, String keyId, long ttlMillis) {
            this.dataKey = dataKey;
            this.keyId = keyId;
            this.expirationTime = System.currentTimeMillis() + ttlMillis;
            this.lastAccessTime = System.currentTimeMillis();
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expirationTime;
        }

        void updateAccessTime() {
            this.lastAccessTime = System.currentTimeMillis();
        }
    }

    /**
     * Constructs a new DataKeyCache with the specified TTL and maximum size.
     *
     * @param ttlMillis the time-to-live for cached keys in milliseconds
     * @param maxSize the maximum number of keys to cache (0 for unlimited)
     */
    public DataKeyCache(long ttlMillis, int maxSize) {
        this.cache = new ConcurrentHashMap<>();
        this.ttlMillis = ttlMillis;
        this.maxSize = maxSize;
        this.refreshLock = new ReentrantReadWriteLock();

        // Start cleanup thread to remove expired entries every 30 seconds
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "data-key-cache-cleanup");
            t.setDaemon(true);
            return t;
        });

        this.cleanupExecutor.scheduleAtFixedRate(this::cleanupExpiredEntries, 30, 30, TimeUnit.SECONDS);

        LOGGER.info("DataKeyCache initialized with TTL: {}ms, maxSize: {}", ttlMillis, maxSize);
    }

    /**
     * Retrieves a data key from cache or generates it using the provided supplier.
     * Automatically handles cache misses and expired entries.
     *
     * @param keyId the unique identifier for the key
     * @param keySupplier supplier function to generate the key on cache miss
     * @return the cached or newly generated data key
     */
    public Key getDataKey(String keyId, Supplier<Key> keySupplier) {
        // Fast path: try to get from cache
        CacheEntry entry = cache.get(keyId);
        if (entry != null && !entry.isExpired()) {
            entry.updateAccessTime();
            LOGGER.debug("Cache hit for keyId: {}", keyId);
            return entry.dataKey;
        }

        // Slow path: refresh key (with double-checked locking)
        refreshLock.writeLock().lock();
        try {
            // Double-check after acquiring lock
            entry = cache.get(keyId);
            if (entry != null && !entry.isExpired()) {
                entry.updateAccessTime();
                LOGGER.debug("Cache hit after lock acquisition for keyId: {}", keyId);
                return entry.dataKey;
            }

            // Cache miss or expired - generate new key
            LOGGER.info("Cache miss for keyId: {}, refreshing from KMS", keyId);
            Key newKey = keySupplier.get();

            // Check size limit before adding
            if (maxSize > 0 && cache.size() >= maxSize) {
                evictLeastRecentlyUsed();
            }

            CacheEntry newEntry = new CacheEntry(newKey, keyId, ttlMillis);
            cache.put(keyId, newEntry);

            LOGGER.info("Successfully cached new key for keyId: {}, expires at: {}", keyId, newEntry.expirationTime);
            return newKey;

        } catch (Exception e) {
            LOGGER.error("Failed to refresh data key for keyId: {}", keyId, e);

            // Return expired key if available as fallback
            if (entry != null) {
                LOGGER.warn("Using expired key as fallback for keyId: {}", keyId);
                return entry.dataKey;
            }

            throw new RuntimeException("Failed to retrieve data key and no fallback available", e);
        } finally {
            refreshLock.writeLock().unlock();
        }
    }

    /**
     * Removes expired entries from the cache.
     */
    private void cleanupExpiredEntries() {
        refreshLock.writeLock().lock();
        try {
            int initialSize = cache.size();
            cache.entrySet().removeIf(entry -> entry.getValue().isExpired());
            int removedCount = initialSize - cache.size();

            if (removedCount > 0) {
                LOGGER.debug("Cleaned up {} expired cache entries", removedCount);
            }
        } finally {
            refreshLock.writeLock().unlock();
        }
    }

    /**
     * Evicts the least recently used entry when cache size limit is reached.
     */
    private void evictLeastRecentlyUsed() {
        String oldestKey = null;
        long oldestAccessTime = Long.MAX_VALUE;

        for (var entry : cache.entrySet()) {
            long accessTime = entry.getValue().lastAccessTime;
            if (accessTime < oldestAccessTime) {
                oldestAccessTime = accessTime;
                oldestKey = entry.getKey();
            }
        }

        if (oldestKey != null) {
            cache.remove(oldestKey);
            LOGGER.debug("Evicted LRU cache entry for keyId: {}", oldestKey);
        }
    }

    /**
     * Invalidates a specific key from the cache.
     *
     * @param keyId the key identifier to invalidate
     */
    public void invalidateKey(String keyId) {
        refreshLock.writeLock().lock();
        try {
            CacheEntry removed = cache.remove(keyId);
            if (removed != null) {
                LOGGER.info("Invalidated cache entry for keyId: {}", keyId);
            }
        } finally {
            refreshLock.writeLock().unlock();
        }
    }

    /**
     * Clears all cached entries.
     */
    public void clear() {
        refreshLock.writeLock().lock();
        try {
            int size = cache.size();
            cache.clear();
            LOGGER.info("Cleared {} cache entries", size);
        } finally {
            refreshLock.writeLock().unlock();
        }
    }

    /**
     * Returns cache statistics for monitoring.
     *
     * @return cache statistics
     */
    public CacheStats getStats() {
        refreshLock.readLock().lock();
        try {
            int totalEntries = cache.size();
            long expiredEntries = cache.values().stream().mapToLong(entry -> entry.isExpired() ? 1 : 0).sum();

            return new CacheStats(totalEntries, expiredEntries, ttlMillis, maxSize);
        } finally {
            refreshLock.readLock().unlock();
        }
    }

    /**
     * Shuts down the cache and cleanup resources.
     */
    public void shutdown() {
        if (cleanupExecutor != null && !cleanupExecutor.isShutdown()) {
            cleanupExecutor.shutdown();
            try {
                if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleanupExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                cleanupExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        clear();
        LOGGER.info("DataKeyCache shutdown completed");
    }

    /**
     * Cache statistics container.
     */
    public static class CacheStats {
        public final int totalEntries;
        public final long expiredEntries;
        public final long ttlMillis;
        public final int maxSize;

        public CacheStats(int totalEntries, long expiredEntries, long ttlMillis, int maxSize) {
            this.totalEntries = totalEntries;
            this.expiredEntries = expiredEntries;
            this.ttlMillis = ttlMillis;
            this.maxSize = maxSize;
        }

        @Override
        public String toString() {
            return String
                .format(
                    "CacheStats{totalEntries=%d, expiredEntries=%d, ttlMillis=%d, maxSize=%d}",
                    totalEntries,
                    expiredEntries,
                    ttlMillis,
                    maxSize
                );
        }
    }
}
