/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.IOException;
import java.nio.file.Path;
import java.security.Provider;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.engine.EngineConfig;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.engine.InternalEngine;
import org.opensearch.index.store.iv.DefaultKeyIvResolver;
import org.opensearch.index.store.iv.KeyIvResolver;
import org.opensearch.index.translog.CryptoTranslogFactory;

/**
 * A factory that creates engines with crypto-enabled translogs for cryptofs indices.
 */
public class CryptoEngineFactory implements EngineFactory {

    private static final Logger logger = LogManager.getLogger(CryptoEngineFactory.class);

    /**
     * Constructor for index-level encryption.
     */
    public CryptoEngineFactory() {
        // No dependencies needed for index-level encryption
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Engine newReadWriteEngine(EngineConfig config) {

        try {
            // Create a separate KeyIvResolver for translog encryption
            KeyIvResolver keyIvResolver = createTranslogKeyIvResolver(config);

            // Create the crypto translog factory using the same KeyIvResolver as the directory
            CryptoTranslogFactory cryptoTranslogFactory = new CryptoTranslogFactory(keyIvResolver);

            // Create new engine config by copying all fields from existing config
            // but replace the translog factory with our crypto version
            EngineConfig cryptoConfig = config
                .toBuilder()
                .translogFactory(cryptoTranslogFactory)  // <- Replace with our crypto factory
                .build();

            // Return the default engine with crypto-enabled translog
            return new InternalEngine(cryptoConfig);
        } catch (IOException e) {
            throw new RuntimeException("Failed to create crypto engine", e);
        }
    }

    /**
     * Create a KeyIvResolver for translog encryption using index-level keys.
     */
    private KeyIvResolver createTranslogKeyIvResolver(EngineConfig config) throws IOException {
        // Use index-level keys for translog encryption - same as directory encryption
        Path translogPath = config.getTranslogConfig().getTranslogPath();

        Path indexDirectory = translogPath.getParent().getParent(); // Go up two levels: translog -> shard -> index

        // Get the same settings that CryptoDirectoryFactory uses
        Provider provider = config.getIndexSettings().getValue(CryptoDirectoryFactory.INDEX_CRYPTO_PROVIDER_SETTING);
        MasterKeyProvider keyProvider = getKeyProvider(config);

        // Create directory for index-level keys (same as CryptoDirectoryFactory)
        Directory indexKeyDirectory = FSDirectory.open(indexDirectory);

        // Use the same DefaultKeyIvResolver with index-level keys
        return new DefaultKeyIvResolver(indexKeyDirectory, provider, keyProvider, config.getIndexSettings().getSettings());
    }

    /**
     * Get the MasterKeyProvider - copied from CryptoDirectoryFactory logic
     */
    private MasterKeyProvider getKeyProvider(EngineConfig config) {
        // Reuse the same logic as CryptoDirectoryFactory
        return new CryptoDirectoryFactory().getKeyProvider(config.getIndexSettings());
    }

}
