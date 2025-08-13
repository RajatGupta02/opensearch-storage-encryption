/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.iv;

import java.security.Key;
import java.time.Duration;
import java.util.Locale;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.stats.CacheStats;

/**
 * Caffeine-based TTL cache for data keys with automatic expiration and size limits.
 * Leverages Google's high-performance Caffeine cache for enterprise-grade caching.
 *
 * @opensearch.internal
 */
public class CaffeineDataKeyCache {

    private static final Logger LOGGER = LogManager.getLogger(CaffeineDataKeyCache.class);

    private final Cache<String, Key> cache;
    private final long ttlMillis;
    private final int maxSize;

    /**
     * Constructs a new CaffeineDataKeyCache with the specified TTL and maximum size.
     *
     * @param ttlMillis the time-to-live for cached keys in milliseconds
     * @param maxSize the maximum number of keys to cache
     */
    public CaffeineDataKeyCache(long ttlMillis, int maxSize) {
        this.ttlMillis = ttlMillis;
        this.maxSize = maxSize;

        this.cache = Caffeine
            .newBuilder()
            .maximumSize(maxSize)
            .expireAfterWrite(Duration.ofMillis(ttlMillis))
            .removalListener(this::onRemoval)
            .recordStats()  // Enable metrics
            .build();

        LOGGER.info("CaffeineDataKeyCache initialized with TTL: {}ms, maxSize: {}", ttlMillis, maxSize);
    }

    /**
     * Retrieves a data key from cache or generates it using the provided supplier.
     * Thread-safe with automatic TTL expiration.
     *
     * @param keyId the unique identifier for the key
     * @param keySupplier supplier function to generate the key on cache miss
     * @return the cached or newly generated data key
     */
    public Key getDataKey(String keyId, Supplier<Key> keySupplier) {
        try {
            Key result = cache.get(keyId, k -> {
                LOGGER.info("Cache miss for keyId: {}, refreshing from KMS", keyId);
                return keySupplier.get();
            });

            if (result != null) {
                LOGGER.debug("Cache hit for keyId: {}", keyId);
            }

            return result;

        } catch (Exception e) {
            LOGGER.error("Failed to retrieve data key for keyId: {}", keyId, e);

            // Try to get expired/existing key as fallback
            Key fallbackKey = cache.getIfPresent(keyId);
            if (fallbackKey != null) {
                LOGGER.warn("Using potentially stale key as fallback for keyId: {}", keyId);
                return fallbackKey;
            }

            throw new RuntimeException("Failed to retrieve data key and no fallback available", e);
        }
    }

    /**
     * Callback for cache entry removal events.
     */
    private void onRemoval(String keyId, Key key, RemovalCause cause) {
        switch (cause) {
            case EXPIRED:
                LOGGER.debug("Key expired and removed from cache: {}", keyId);
                break;
            case SIZE:
                LOGGER.debug("Key evicted due to size limit: {}", keyId);
                break;
            case EXPLICIT:
                LOGGER.debug("Key explicitly removed from cache: {}", keyId);
                break;
            default:
                LOGGER.debug("Key removed from cache due to {}: {}", cause, keyId);
        }
    }

    /**
     * Invalidates a specific key from the cache.
     *
     * @param keyId the key identifier to invalidate
     */
    public void invalidateKey(String keyId) {
        cache.invalidate(keyId);
        LOGGER.info("Invalidated cache entry for keyId: {}", keyId);
    }

    /**
     * Clears all cached entries.
     */
    public void clear() {
        long size = cache.estimatedSize();
        cache.invalidateAll();
        LOGGER.info("Cleared {} cache entries", size);
    }

    /**
     * Returns cache statistics for monitoring.
     *
     * @return Caffeine's built-in cache statistics
     */
    public CacheStatistics getStats() {
        CacheStats stats = cache.stats();
        return new CacheStatistics(
            cache.estimatedSize(),
            stats.hitCount(),
            stats.missCount(),
            stats.evictionCount(),
            stats.averageLoadPenalty(),
            ttlMillis,
            maxSize
        );
    }

    /**
     * Shuts down the cache (Caffeine handles cleanup automatically).
     */
    public void shutdown() {
        clear();
        LOGGER.info("CaffeineDataKeyCache shutdown completed");
    }

    /**
     * Cache statistics container with additional OpenSearch-specific metrics.
     */
    public static class CacheStatistics {
        public final long estimatedSize;
        public final long hitCount;
        public final long missCount;
        public final long evictionCount;
        public final double averageLoadTimeNanos;
        public final long ttlMillis;
        public final int maxSize;

        public CacheStatistics(
            long estimatedSize,
            long hitCount,
            long missCount,
            long evictionCount,
            double averageLoadTimeNanos,
            long ttlMillis,
            int maxSize
        ) {
            this.estimatedSize = estimatedSize;
            this.hitCount = hitCount;
            this.missCount = missCount;
            this.evictionCount = evictionCount;
            this.averageLoadTimeNanos = averageLoadTimeNanos;
            this.ttlMillis = ttlMillis;
            this.maxSize = maxSize;
        }

        public double getHitRate() {
            long totalRequests = hitCount + missCount;
            return totalRequests == 0 ? 0.0 : (double) hitCount / totalRequests;
        }

        @Override
        public String toString() {
            return String
                .format(
                    Locale.ROOT,
                    "CacheStats{size=%d, hits=%d, misses=%d, hitRate=%.2f%%, evictions=%d, avgLoadTimeMs=%.2f, ttl=%dms, maxSize=%d}",
                    estimatedSize,
                    hitCount,
                    missCount,
                    getHitRate() * 100,
                    evictionCount,
                    averageLoadTimeNanos / 1_000_000.0,
                    ttlMillis,
                    maxSize
                );
        }
    }
}
