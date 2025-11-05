/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.iv;

import java.security.Key;
import java.util.Objects;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.store.CryptoDirectoryFactory;

import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;

/**
 * Node-level cache for encryption keys used across all indices.
 * Provides centralized key management with global TTL configuration and failure handling.
 * 
 * This cache replaces the per-resolver Caffeine caches to reduce memory overhead
 * and provide better cache utilization across indices.
 * 
 * <p>Failure Handling Strategy:
 * <ul>
 *   <li>Keys are refreshed in background at TTL intervals (default: 1 hour)</li>
 *   <li>On refresh failure, old key is retained temporarily</li>
 *   <li>After multiple consecutive failures (default: 3), keys expire</li>
 *   <li>Load retries are throttled to prevent DOS (default: 5 minutes between attempts)</li>
 *   <li>System automatically recovers when Master Key Provider is restored</li>
 * </ul>
 * 
 * @opensearch.internal
 */
public class NodeLevelKeyCache {

    private static final Logger logger = LogManager.getLogger(NodeLevelKeyCache.class);

    private static NodeLevelKeyCache INSTANCE;

    private final LoadingCache<CacheKey, Key> keyCache;
    private final long globalTtlSeconds;
    private final int expiryMultiplier;
    private final long retryIntervalSeconds;

    // Track failures per index to implement DOS protection and retry throttling
    private final ConcurrentHashMap<String, FailureState> failureTracker;

    /**
     * Tracks failure state for an index to implement retry throttling.
     */
    static class FailureState {
        final AtomicLong lastFailureTimeMillis;
        final AtomicReference<Exception> lastException;

        FailureState(Exception exception) {
            this.lastFailureTimeMillis = new AtomicLong(System.currentTimeMillis());
            this.lastException = new AtomicReference<>(exception);
        }

        void recordFailure(Exception exception) {
            lastFailureTimeMillis.set(System.currentTimeMillis());
            lastException.set(exception);
        }

        long getSecondsSinceLastFailure() {
            return (System.currentTimeMillis() - lastFailureTimeMillis.get()) / 1000;
        }
    }

    /**
     * Cache key that contains the index UUID and resolver.
     * The resolver is passed directly to eliminate registry lookup race conditions.
     * Note: equals/hashCode use only indexUuid to ensure cache sharing across resolver instances.
     */
    static class CacheKey {
        final String indexUuid;
        final DefaultKeyIvResolver resolver;

        CacheKey(String indexUuid, DefaultKeyIvResolver resolver) {
            this.indexUuid = Objects.requireNonNull(indexUuid, "indexUuid cannot be null");
            this.resolver = Objects.requireNonNull(resolver, "resolver cannot be null");
        }

        // For eviction - no resolver needed
        CacheKey(String indexUuid) {
            this.indexUuid = Objects.requireNonNull(indexUuid, "indexUuid cannot be null");
            this.resolver = null;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (!(o instanceof CacheKey))
                return false;
            CacheKey that = (CacheKey) o;
            return Objects.equals(indexUuid, that.indexUuid);
        }

        @Override
        public int hashCode() {
            return Objects.hash(indexUuid);
        }

        @Override
        public String toString() {
            return "CacheKey[indexUuid=" + indexUuid + "]";
        }
    }

    /**
     * Initializes the singleton instance with node-level settings.
     * This should be called once during plugin initialization.
     * 
     * @param nodeSettings the node settings containing global TTL configuration
     */
    public static synchronized void initialize(Settings nodeSettings) {
        if (INSTANCE == null) {
            int globalTtlSeconds = CryptoDirectoryFactory.NODE_KEY_REFRESH_INTERVAL_SECS_SETTING.get(nodeSettings);
            int expiryMultiplier = CryptoDirectoryFactory.NODE_KEY_EXPIRY_MULTIPLIER_SETTING.get(nodeSettings);
            int retryIntervalSeconds = CryptoDirectoryFactory.NODE_KEY_RETRY_INTERVAL_SECS_SETTING.get(nodeSettings);

            INSTANCE = new NodeLevelKeyCache((long) globalTtlSeconds, expiryMultiplier, (long) retryIntervalSeconds);

            if (globalTtlSeconds == -1) {
                logger.info("Initialized NodeLevelKeyCache with refresh disabled (TTL: -1)");
            } else {
                logger
                    .info(
                        "Initialized NodeLevelKeyCache with refresh TTL: {} seconds, expiry multiplier: {}, retry interval: {} seconds",
                        globalTtlSeconds,
                        expiryMultiplier,
                        retryIntervalSeconds
                    );
            }
        }
    }

    /**
     * Gets the singleton instance.
     * 
     * @return the NodeLevelKeyCache instance
     * @throws IllegalStateException if the cache has not been initialized
     */
    public static NodeLevelKeyCache getInstance() {
        if (INSTANCE == null) {
            throw new IllegalStateException("NodeLevelKeyCache not initialized.");
        }
        return INSTANCE;
    }

    /**
     * Constructs the cache with global TTL and expiration configuration.
     * <p>
     * This implements a cache with asynchronous refresh and failure-based expiration:
     * <ul>
     *  <li>When a key is first requested, it is loaded synchronously from the MasterKey Provider.</li>
     * 
     *  <li>After the key has been in the cache for the refresh TTL duration, 
     *      the next access triggers an asynchronous reload in the background.</li>
     * 
     *  <li>While the reload is in progress, it continues to return the 
     *      previously cached (stale) value to avoid blocking operations.</li>
     * 
     *  <li>If the reload fails, an exception is thrown (not suppressed), allowing Caffeine to track failures.</li>
     * 
     *  <li>After consecutive failures for the expiry duration (refreshTTL * expiryMultiplier),
     *      the entry is evicted from the cache.</li>
     * 
     *  <li>Load attempts are throttled with a minimum retry interval to prevent DOS on Master Key Provider.</li>
     * 
     *  <li>When Master Key Provider is restored, the next get() will trigger a fresh load and recover automatically.</li>
     * </ul>
     * 
     * @param globalTtlSeconds the refresh TTL in seconds (-1 means never refresh)
     * @param expiryMultiplier multiplier for expiration (expiryTime = refreshTTL * multiplier)
     * @param retryIntervalSeconds minimum seconds between load retry attempts
     */
    private NodeLevelKeyCache(long globalTtlSeconds, int expiryMultiplier, long retryIntervalSeconds) {
        this.globalTtlSeconds = globalTtlSeconds;
        this.expiryMultiplier = expiryMultiplier;
        this.retryIntervalSeconds = retryIntervalSeconds;
        this.failureTracker = new ConcurrentHashMap<>();

        // Check if refresh is disabled
        if (globalTtlSeconds == -1L) {
            // Create cache without refresh
            this.keyCache = Caffeine
                .newBuilder()
                // No refreshAfterWrite - keys are loaded once and cached forever
                .build(new CacheLoader<CacheKey, Key>() {
                    @Override
                    public Key load(CacheKey key) throws Exception {
                        return loadKeyWithThrottling(key);
                    }
                    // No reload method needed since refresh is disabled
                });
        } else {
            // Create cache with refresh and expiration policy
            // Keys refresh at TTL intervals, expire after TTL * multiplier on consecutive failures
            this.keyCache = Caffeine
                .newBuilder()
                .refreshAfterWrite(globalTtlSeconds, TimeUnit.SECONDS)
                .expireAfterWrite(globalTtlSeconds * expiryMultiplier, TimeUnit.SECONDS)
                .build(new CacheLoader<CacheKey, Key>() {
                    @Override
                    public Key load(CacheKey key) throws Exception {
                        return loadKeyWithThrottling(key);
                    }

                    @Override
                    public Key reload(CacheKey key, Key oldValue) throws Exception {
                        // Use the resolver provided in the cache key for refresh
                        if (key.resolver == null) {
                            // Fallback: try to get from registry if not provided (shouldn't happen)
                            KeyIvResolver resolver = IndexKeyResolverRegistry.getResolver(key.indexUuid);
                            if (resolver == null) {
                                logger.warn("Resolver not found for index {} during reload, index may have been deleted", key.indexUuid);
                                // Throw exception to let cache track failure
                                throw new IllegalStateException("Resolver not found for index: " + key.indexUuid);
                            }
                            Key newKey = ((DefaultKeyIvResolver) resolver).loadKeyFromMasterKeyProvider();
                            // Clear failure state on successful reload
                            failureTracker.remove(key.indexUuid);
                            logger.info("Successfully reloaded key for index: {}", key.indexUuid);
                            return newKey;
                        }

                        try {
                            Key newKey = key.resolver.loadKeyFromMasterKeyProvider();
                            // Clear failure state on successful reload
                            failureTracker.remove(key.indexUuid);
                            logger.info("Successfully reloaded key for index: {}", key.indexUuid);
                            return newKey;
                        } catch (Exception e) {
                            // Track the failure
                            failureTracker.computeIfAbsent(key.indexUuid, k -> new FailureState(e)).recordFailure(e);
                            // logger.warn("Failed to reload key for index: {}, error: {}", key.indexUuid, e.getMessage());
                            // Wrap exception to suppress stack trace and avoid log spam
                            throw new KeyCacheException("Failed to reload key for index: " + key.indexUuid, e, true);
                        }
                    }
                });
        }
    }

    /**
     * Loads a key with retry throttling to prevent DOS on Master Key Provider.
     * If a recent load attempt failed, this method will not retry until the retry interval has passed.
     * 
     * @param key the cache key
     * @return the loaded encryption key
     * @throws Exception if key loading fails
     */
    private Key loadKeyWithThrottling(CacheKey key) throws Exception {
        if (key.resolver == null) {
            throw new IllegalStateException("Resolver not provided for index: " + key.indexUuid);
        }

        // Check if we should throttle retry attempts
        FailureState state = failureTracker.get(key.indexUuid);
        if (state != null) {
            long secondsSinceLastFailure = state.getSecondsSinceLastFailure();
            if (secondsSinceLastFailure < retryIntervalSeconds) {
                logger
                    .debug(
                        "Throttling load retry for index: {}, {} seconds since last failure (minimum: {} seconds)",
                        key.indexUuid,
                        secondsSinceLastFailure,
                        retryIntervalSeconds
                    );
                // Re-throw the last exception without attempting a new load
                Exception lastException = state.lastException.get();
                // Wrap if not already a KeyCacheException to avoid double-wrapping
                if (lastException instanceof KeyCacheException) {
                    throw lastException;
                } else {
                    throw new KeyCacheException("Throttled load retry for index: " + key.indexUuid, lastException, true);
                }
            }
        }

        try {
            Key loadedKey = key.resolver.loadKeyFromMasterKeyProvider();
            // Clear failure state on successful load
            failureTracker.remove(key.indexUuid);
            logger.info("Successfully loaded key for index: {}", key.indexUuid);
            return loadedKey;
        } catch (Exception e) {
            // Track the failure with current timestamp
            failureTracker.computeIfAbsent(key.indexUuid, k -> new FailureState(e)).recordFailure(e);
            // logger.error("Failed to load key for index: {}, error: {}", key.indexUuid, e.getMessage());
            // Wrap exception to suppress stack trace and avoid log spam
            throw new KeyCacheException("Failed to load key for index: " + key.indexUuid, e, true);
        }
    }

    /**
     * Gets a key from the cache, loading it if necessary.
     * 
     * @param indexUuid the index UUID
     * @param resolver the resolver to use for loading the key (eliminates registry lookup race condition)
     * @return the encryption key
     * @throws Exception if key loading fails
     */
    public Key get(String indexUuid, DefaultKeyIvResolver resolver) throws Exception {
        Objects.requireNonNull(indexUuid, "indexUuid cannot be null");
        Objects.requireNonNull(resolver, "resolver cannot be null");

        try {
            return keyCache.get(new CacheKey(indexUuid, resolver));
        } catch (CompletionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            } else {
                throw new RuntimeException("Failed to get key from cache", cause);
            }
        }
    }

    /**
     * Evicts a key from the cache.
     * This should be called when an index is deleted.
     * @param indexUuid the index UUID
     */
    public void evict(String indexUuid) {
        Objects.requireNonNull(indexUuid, "indexUuid cannot be null");
        keyCache.invalidate(new CacheKey(indexUuid));
        failureTracker.remove(indexUuid);
        logger.debug("Evicted key and cleared failure state for index: {}", indexUuid);
    }

    /**
     * Gets the number of cached keys.
     * Useful for monitoring and testing.
     * 
     * @return the number of cached keys
     */
    public long size() {
        return keyCache.estimatedSize();
    }

    /**
     * Clears all cached keys and failure states.
     * This method is primarily for testing purposes.
     */
    public void clear() {
        keyCache.invalidateAll();
        failureTracker.clear();
    }

    /**
     * Resets the singleton instance.
     * This method is primarily for testing purposes.
     */
    public static synchronized void reset() {
        if (INSTANCE != null) {
            INSTANCE.clear();
            INSTANCE = null;
        }
    }
}
