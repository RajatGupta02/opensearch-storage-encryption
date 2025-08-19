/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.store.iv.NodeKeyIvResolver;

/**
 * Node-level service for managing encryption keys and IVs.
 * Provides shared KeyIvResolvers for indices with the same KMS configuration.
 * Keys are stored at the node level but resolvers are created per unique KMS settings.
 * 
 * @opensearch.internal
 */
public class NodeKeyService {

    private static final Logger logger = LogManager.getLogger(NodeKeyService.class);

    private final Path nodeStatePath;
    private final ConcurrentHashMap<String, NodeKeyIvResolver> resolverCache = new ConcurrentHashMap<>();

    /**
     * Creates a new NodeKeyService with node-level key storage.
     * 
     * @param nodeEnv the node environment to determine the _state directory path
     * @param nodeSettings the node-level settings (not used for crypto config)
     * @throws IOException if there's an error creating the _state directory
     */
    public NodeKeyService(NodeEnvironment nodeEnv, Settings nodeSettings) throws IOException {
        // Use the first data path to store node-level keys in _state directory
        this.nodeStatePath = nodeEnv.nodeDataPaths()[0].resolve("_state");
        Files.createDirectories(nodeStatePath);

        logger.info("Node-level encryption service initialized with key storage at: {}", nodeStatePath);
    }

    /**
     * Returns a KeyIvResolver for the given index settings.
     * Resolvers are cached and shared between indices with the same KMS configuration.
     * 
     * @param indexSettings the index settings containing KMS configuration
     * @return the KeyIvResolver for this configuration
     * @throws IOException if there's an error creating the resolver
     */
    public synchronized NodeKeyIvResolver getResolver(IndexSettings indexSettings) throws IOException {
        // Create a cache key based on KMS settings
        String kmsType = indexSettings.getValue(CryptoDirectoryFactory.INDEX_KMS_TYPE_SETTING);
        String cryptoProvider = indexSettings.getValue(CryptoDirectoryFactory.INDEX_CRYPTO_PROVIDER_SETTING).getName();
        Integer ttl = indexSettings.getValue(CryptoDirectoryFactory.KMS_DATA_KEY_TTL_SECONDS_SETTING);

        String cacheKey = String.format("%s-%s-%d", kmsType, cryptoProvider, ttl);

        return resolverCache.computeIfAbsent(cacheKey, key -> {
            try {
                // Create a subdirectory for this KMS configuration
                Path configPath = nodeStatePath.resolve("crypto-" + cacheKey.hashCode());
                Files.createDirectories(configPath);

                // Build settings for this configuration
                Settings resolverSettings = Settings
                    .builder()
                    .put("cluster.encryption.kms.type", kmsType)
                    .put("cluster.encryption.kms.data_key_ttl_seconds", ttl)
                    .put("cluster.encryption.crypto.provider", cryptoProvider)
                    .build();

                logger.info("Creating new node-level resolver for KMS config: {} at path: {}", cacheKey, configPath);
                return new NodeKeyIvResolver(configPath, resolverSettings);
            } catch (IOException e) {
                throw new RuntimeException("Failed to create NodeKeyIvResolver for config: " + cacheKey, e);
            }
        });
    }
}
