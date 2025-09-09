/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.IOException;
import java.security.Provider;
import java.util.Objects;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.engine.EngineConfig;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.engine.InternalEngine;
import org.opensearch.index.store.iv.KeyIvResolver;
import org.opensearch.index.store.iv.SystemIndexKeyIvResolver;
import org.opensearch.index.store.systemindex.SystemIndexManager;
import org.opensearch.index.translog.CryptoTranslogFactory;
import org.opensearch.transport.client.Client;

/**
 * A factory that creates engines with crypto-enabled translogs for cryptofs indices.
 * Uses system index-based key storage for translog encryption.
 */
public class CryptoEngineFactory implements EngineFactory {

    private static final Logger logger = LogManager.getLogger(CryptoEngineFactory.class);

    private final Supplier<Client> clientSupplier;
    private final Supplier<SystemIndexManager> systemIndexManagerSupplier;

    /**
     * Constructor for system index-based encryption with lazy client and SystemIndexManager resolution.
     * 
     * @param clientSupplier supplier that provides the client when needed
     * @param systemIndexManagerSupplier supplier that provides the SystemIndexManager when needed
     */
    public CryptoEngineFactory(Supplier<Client> clientSupplier, Supplier<SystemIndexManager> systemIndexManagerSupplier) {
        this.clientSupplier = Objects.requireNonNull(clientSupplier, "Client supplier cannot be null");
        this.systemIndexManagerSupplier = Objects.requireNonNull(systemIndexManagerSupplier, "SystemIndexManager supplier cannot be null");
    }

    /**
     * Gets the client with proper error handling for initialization timing issues.
     * 
     * @return the OpenSearch client
     * @throws IllegalStateException if client is not yet available
     */
    private Client getClient() {
        Client client = clientSupplier.get();
        if (client == null) {
            throw new IllegalStateException(
                "Client not available for translog encryption - OpenSearch may still be initializing. "
                    + "This typically happens during plugin startup."
            );
        }
        return client;
    }

    /**
     * Gets the SystemIndexManager with proper error handling for initialization timing issues.
     * 
     * @return the SystemIndexManager
     * @throws IllegalStateException if SystemIndexManager is not yet available
     */
    private SystemIndexManager getSystemIndexManager() {
        SystemIndexManager manager = systemIndexManagerSupplier.get();
        if (manager == null) {
            throw new IllegalStateException(
                "SystemIndexManager not available for translog encryption - OpenSearch may still be initializing. "
                    + "This typically happens during plugin startup."
            );
        }
        return manager;
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
     * Create a KeyIvResolver for translog encryption using the same system index approach
     * as CryptoDirectoryFactory. This ensures both directory and translog use the same keys.
     */
    private KeyIvResolver createTranslogKeyIvResolver(EngineConfig config) throws IOException {
        // Get the same settings that CryptoDirectoryFactory uses
        Provider provider = config.getIndexSettings().getValue(CryptoDirectoryFactory.INDEX_CRYPTO_PROVIDER_SETTING);
        MasterKeyProvider keyProvider = getKeyProvider(config);
        String indexUuid = config.getIndexSettings().getIndex().getUUID();
        String kmsKeyId = config.getIndexSettings().getValue(CryptoDirectoryFactory.INDEX_KMS_KEY_ID_SETTING);

        // Use system index-based key storage - same as CryptoDirectoryFactory
        return new SystemIndexKeyIvResolver(
            getClient(),
            indexUuid,
            kmsKeyId,
            provider,
            keyProvider,
            config.getIndexSettings().getSettings(),
            getSystemIndexManager()
        );
    }

    /**
     * Get the MasterKeyProvider - copied from CryptoDirectoryFactory logic
     */
    private MasterKeyProvider getKeyProvider(EngineConfig config) {
        // Reuse the same logic as CryptoDirectoryFactory
        return new CryptoDirectoryFactory(() -> getClient(), () -> getSystemIndexManager()).getKeyProvider(config.getIndexSettings());
    }

}
