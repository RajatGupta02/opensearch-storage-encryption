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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Metadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.store.CryptoDirectoryFactory;
import org.opensearch.transport.client.Client;

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
    private final Client client;
    private final ClusterService clusterService;

    // Track failures per index to implement write block protection
    private final ConcurrentHashMap<String, FailureState> failureTracker;

    /**
     * Tracks failure state for an index and closed status.
     */
    static class FailureState {
        final AtomicLong lastFailureTimeMillis;
        final AtomicReference<Exception> lastException;
        final AtomicInteger consecutiveFailures;
        volatile boolean indexClosed = false;

        FailureState(Exception exception) {
            this.lastFailureTimeMillis = new AtomicLong(System.currentTimeMillis());
            this.lastException = new AtomicReference<>(exception);
            this.consecutiveFailures = new AtomicInteger(1);
        }

        void recordFailure(Exception exception) {
            lastFailureTimeMillis.set(System.currentTimeMillis());
            lastException.set(exception);
            consecutiveFailures.incrementAndGet();
        }

        int getConsecutiveFailures() {
            return consecutiveFailures.get();
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
     * Initializes the singleton instance with node-level settings, client, and cluster service.
     * This should be called once during plugin initialization.
     * 
     * @param nodeSettings the node settings containing global TTL configuration
     * @param client the client for cluster state updates (write block operations)
     * @param clusterService the cluster service for looking up index metadata
     */
    public static synchronized void initialize(Settings nodeSettings, Client client, ClusterService clusterService) {
        if (INSTANCE == null) {
            int globalTtlSeconds = CryptoDirectoryFactory.NODE_KEY_REFRESH_INTERVAL_SECS_SETTING.get(nodeSettings);
            int expiryMultiplier = CryptoDirectoryFactory.NODE_KEY_EXPIRY_MULTIPLIER_SETTING.get(nodeSettings);

            INSTANCE = new NodeLevelKeyCache((long) globalTtlSeconds, expiryMultiplier, client, clusterService);

            if (globalTtlSeconds == -1) {
                logger.info("Initialized NodeLevelKeyCache with refresh disabled (TTL: -1)");
            } else {
                logger
                    .info(
                        "Initialized NodeLevelKeyCache with refresh TTL: {} seconds, expiry multiplier: {}",
                        globalTtlSeconds,
                        expiryMultiplier
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
     *  <li>On first load failure after cache expiry, a close on index is applied to prevent log spam.</li>
     * 
     *  <li>When Master Key Provider is restored, the closed index is automatically opened again.</li>
     * </ul>
     * 
     * @param globalTtlSeconds the refresh TTL in seconds (-1 means never refresh)
     * @param expiryMultiplier multiplier for expiration (expiryTime = refreshTTL * multiplier)
     */
    private NodeLevelKeyCache(long globalTtlSeconds, int expiryMultiplier, Client client, ClusterService clusterService) {
        this.globalTtlSeconds = globalTtlSeconds;
        this.expiryMultiplier = expiryMultiplier;
        this.client = client;
        this.clusterService = clusterService;
        this.failureTracker = new ConcurrentHashMap<>();

        // Suppress Caffeine's internal logging to reduce log spam during key reload failures
        // This prevents duplicate exception logging from Caffeine's BoundedLocalCache
        java.util.logging.Logger.getLogger("com.github.benmanes.caffeine.cache").setLevel(java.util.logging.Level.SEVERE);

        // Check if refresh is disabled
        if (globalTtlSeconds == -1L) {
            // Create cache without refresh
            this.keyCache = Caffeine
                .newBuilder()
                // No refreshAfterWrite - keys are loaded once and cached forever
                .build(new CacheLoader<CacheKey, Key>() {
                    @Override
                    public Key load(CacheKey key) throws Exception {
                        return loadKey(key);
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
                        return loadKey(key);
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
                            // Get or create failure state, but don't double-count on first failure
                            FailureState state = failureTracker.get(key.indexUuid);
                            if (state == null) {
                                // First failure - create with count = 1
                                state = new FailureState(e);
                                failureTracker.put(key.indexUuid, state);
                            } else {
                                // Subsequent failure - increment count
                                state.recordFailure(e);
                            }

                            int failureCount = state.getConsecutiveFailures();

                            // Apply blocks after (expiryMultiplier - 1) consecutive failures
                            // This allows operations to complete with the cached key before blocks are applied
                            if (failureCount == expiryMultiplier - 1 && !state.indexClosed) {
                                applyBlocks(key.indexUuid);
                                state.indexClosed = true;
                                logger
                                    .warn(
                                        "Applied read+write blocks after {} consecutive reload failures (before cache expiry): {}",
                                        failureCount,
                                        key.indexUuid
                                    );
                            }

                            throw new KeyCacheException(
                                "Failed to reload key for index: " + key.indexUuid + ". Error: " + e.getMessage(),
                                null,  // No cause - eliminates ~40 lines of AWS SDK stack trace
                                true
                            );
                        }
                    }
                });
        }
    }

    /**
     * Loads a key from Master Key Provider and handles failures by applying closed index.
     * 
     * @param key the cache key
     * @return the loaded encryption key
     * @throws Exception if key loading fails
     */
    private Key loadKey(CacheKey key) throws Exception {
        if (key.resolver == null) {
            throw new IllegalStateException("Resolver not provided for index: " + key.indexUuid);
        }

        try {
            Key loadedKey = key.resolver.loadKeyFromMasterKeyProvider();

            // Success! Check if blocks exist before attempting removal
            if (hasBlocks(key.indexUuid)) {
                removeBlocks(key.indexUuid);
            }

            // Clear failure state on successful load
            failureTracker.remove(key.indexUuid);

            logger.info("Successfully loaded key for index: {}", key.indexUuid);
            return loadedKey;

        } catch (Exception e) {
            // Get existing failure state (may exist from failed reload)
            FailureState state = failureTracker.get(key.indexUuid);

            // If blocks already applied (from reload failures), fail fast without retry
            if (state != null && state.indexClosed) {
                logger.info("Blocks already applied, failing fast for UUID: {}", key.indexUuid);
                throw new KeyCacheException("Index blocked due to key unavailability: " + key.indexUuid, null, true);
            }

            // First load failure after cache expiry - apply blocks immediately
            if (state == null) {
                state = new FailureState(e);
                failureTracker.put(key.indexUuid, state);
            } else {
                state.recordFailure(e);
            }

            applyBlocks(key.indexUuid);
            state.indexClosed = true;
            logger.error("Applied blocks to index: {} due to key load failure", key.indexUuid);

            // Wrap exception to suppress stack trace and avoid log spam
            throw new KeyCacheException("Failed to load key for index: " + key.indexUuid + ". Error: " + e.getMessage(), null, true);
        }
    }

    /**
     * Gets the index name for a given UUID from the cluster state.
     * 
     * @param indexUuid the index UUID
     * @return the index name, or null if not found
     */
    private String getIndexNameFromUuid(String indexUuid) {
        try {
            Metadata metadata = clusterService.state().metadata();
            for (IndexMetadata indexMetadata : metadata.indices().values()) {
                if (indexMetadata.getIndexUUID().equals(indexUuid)) {
                    return indexMetadata.getIndex().getName();
                }
            }
            return null;
        } catch (Exception e) {
            logger.error("Failed to lookup index name for UUID: {}", indexUuid, e);
            return null;
        }
    }

    /**
     * Checks if read or write blocks are currently applied to the index.
     * 
     * @param indexUuid the index UUID
     * @return true if either read or write blocks are applied, false otherwise
     */
    private boolean hasBlocks(String indexUuid) {
        try {
            Metadata metadata = clusterService.state().metadata();
            for (IndexMetadata indexMetadata : metadata.indices().values()) {
                if (indexMetadata.getIndexUUID().equals(indexUuid)) {
                    Settings indexSettings = indexMetadata.getSettings();

                    // Check for read or write blocks
                    boolean readBlock = indexSettings.getAsBoolean("index.blocks.read", false);
                    boolean writeBlock = indexSettings.getAsBoolean("index.blocks.write", false);

                    return readBlock || writeBlock;
                }
            }
            return false; // Index not found
        } catch (Exception e) {
            logger.warn("Failed to check blocks for index UUID: {}", indexUuid, e);
            return false; // Assume no blocks on error
        }
    }

    /**
     * Applies read and write blocks to the specified index to prevent all operations 
     * when encryption key is unavailable. This provides security by blocking access 
     * to data that cannot be properly decrypted.
     * 
     * Note: Blocks do not persist through blue-green deployments and require manual 
     * removal after KMS recovery.
     * 
     * @param indexUuid the index UUID
     */
    private void applyBlocks(String indexUuid) {
        try {
            // Get index name from UUID via cluster state
            String indexName = getIndexNameFromUuid(indexUuid);
            if (indexName == null) {
                logger.warn("Cannot apply blocks: index name not found for UUID: {}", indexUuid);
                return;
            }

            // Apply both read and write blocks
            Settings settings = Settings.builder().put("index.blocks.read", true).put("index.blocks.write", true).build();

            UpdateSettingsRequest request = new UpdateSettingsRequest(settings, indexName);
            client.admin().indices().updateSettings(request).actionGet();

            logger.info("Successfully applied read+write blocks to index: {}", indexName);
        } catch (Exception e) {
            logger.error("Failed to apply blocks to index UUID: {}, error: {}", indexUuid, e.getMessage(), e);
        }
    }

    /**
     * Removes read and write blocks from the specified index when the encryption key 
     * becomes available again. This restores full access after key recovery.
     * 
     * @param indexUuid the index UUID
     */
    private void removeBlocks(String indexUuid) {
        try {
            // Get index name from UUID via cluster state
            String indexName = getIndexNameFromUuid(indexUuid);
            if (indexName == null) {
                logger.warn("Cannot remove blocks: index name not found for UUID: {}", indexUuid);
                return;
            }

            // Remove both read and write blocks
            Settings settings = Settings.builder().putNull("index.blocks.read").putNull("index.blocks.write").build();

            UpdateSettingsRequest request = new UpdateSettingsRequest(settings, indexName);
            client.admin().indices().updateSettings(request).actionGet();

            logger.info("Successfully removed read+write blocks from index: {}", indexName);
        } catch (Exception e) {
            logger.error("Failed to remove blocks from index UUID: {}, error: {}", indexUuid, e.getMessage(), e);
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
