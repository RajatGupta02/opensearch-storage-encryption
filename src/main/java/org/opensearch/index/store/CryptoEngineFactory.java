/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.IOException;

import org.apache.lucene.store.Directory;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.engine.EngineConfig;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.engine.InternalEngine;
import org.opensearch.index.store.iv.KeyIvResolver;
import org.opensearch.index.store.niofs.CryptoNIOFSDirectory;
import org.opensearch.index.translog.CryptoTranslogFactory;

/**
 * A factory that creates engines with crypto-enabled translogs for cryptofs indices.
 * Updated to use unified KeyIvResolver approach for consistent key management
 * between index files and translog files.
 */
public class CryptoEngineFactory implements EngineFactory {

    /**
     * Default constructor.
     */
    public CryptoEngineFactory() {}

    /**
     * {@inheritDoc}
     */
    @Override
    public Engine newReadWriteEngine(EngineConfig config) {
        try {
            // Get the KeyIvResolver from the crypto directory
            KeyIvResolver keyIvResolver = extractKeyIvResolver(config);

            // Create the crypto translog factory using the same KeyIvResolver as the directory
            CryptoTranslogFactory cryptoTranslogFactory = new CryptoTranslogFactory(keyIvResolver);

            // Create new engine config by copying all fields from existing config
            // but replace the translog factory with our crypto version
            EngineConfig cryptoConfig = new EngineConfig.Builder()
                .shardId(config.getShardId())
                .threadPool(config.getThreadPool())
                .indexSettings(config.getIndexSettings())
                .warmer(config.getWarmer())
                .store(config.getStore())
                .mergePolicy(config.getMergePolicy())
                .analyzer(config.getAnalyzer())
                .similarity(config.getSimilarity())
                .codecService(getCodecService(config))
                .eventListener(config.getEventListener())
                .queryCache(config.getQueryCache())
                .queryCachingPolicy(config.getQueryCachingPolicy())
                .translogConfig(config.getTranslogConfig())
                .translogDeletionPolicyFactory(config.getCustomTranslogDeletionPolicyFactory())
                .flushMergesAfter(config.getFlushMergesAfter())
                .externalRefreshListener(config.getExternalRefreshListener())
                .internalRefreshListener(config.getInternalRefreshListener())
                .indexSort(config.getIndexSort())
                .circuitBreakerService(config.getCircuitBreakerService())
                .globalCheckpointSupplier(config.getGlobalCheckpointSupplier())
                .retentionLeasesSupplier(config.retentionLeasesSupplier())
                .primaryTermSupplier(config.getPrimaryTermSupplier())
                .tombstoneDocSupplier(config.getTombstoneDocSupplier())
                .readOnlyReplica(config.isReadOnlyReplica())
                .startedPrimarySupplier(config.getStartedPrimarySupplier())
                .translogFactory(cryptoTranslogFactory)  // <- Replace with our crypto factory
                .leafSorter(config.getLeafSorter())
                .documentMapperForTypeSupplier(config.getDocumentMapperForTypeSupplier())
                .indexReaderWarmer(config.getIndexReaderWarmer())
                .clusterApplierService(config.getClusterApplierService())
                .build();

            // Return the default engine with crypto-enabled translog
            return new InternalEngine(cryptoConfig);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create crypto engine", e);
        }
    }

    /**
     * Extract the KeyIvResolver from the crypto directory.
     * This ensures translog uses the same keys as index files.
     */
    private KeyIvResolver extractKeyIvResolver(EngineConfig config) throws IOException {
        Directory directory = config.getStore().directory();

        // The directory should be a crypto directory that contains a KeyIvResolver
        if (directory instanceof CryptoNIOFSDirectory) {
            return ((CryptoNIOFSDirectory) directory).keyIvResolver;
        }

        // If we reach here, it means the CryptoEngineFactory is being used
        // with a non-crypto directory, which shouldn't happen in normal operation
        throw new IllegalStateException(
            "CryptoEngineFactory can only be used with CryptoNIOFSDirectory. " + "Directory type: " + directory.getClass().getSimpleName()
        );
    }

    /**
     * Helper method to create a CodecService from existing EngineConfig.
     * Since EngineConfig doesn't expose CodecService directly, we create a new one
     * using the same IndexSettings.
     */
    private org.opensearch.index.codec.CodecService getCodecService(EngineConfig config) {
        // Create a CodecService using the same IndexSettings as the original config
        // We pass null for MapperService and use a simple logger since we're just
        // preserving the existing codec behavior
        return new org.opensearch.index.codec.CodecService(
            null, // MapperService - null is acceptable for basic codec functionality
            config.getIndexSettings(),
            org.apache.logging.log4j.LogManager.getLogger(CryptoEngineFactory.class)
        );
    }
}
