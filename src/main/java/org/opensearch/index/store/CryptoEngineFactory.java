/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.io.IOException;
import java.util.Objects;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.engine.Engine;
import org.opensearch.index.engine.EngineConfig;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.engine.InternalEngine;
import org.opensearch.index.store.iv.KeyIvResolver;
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
    private final Supplier<CryptoDirectoryPlugin> pluginSupplier;

    /**
     * Constructor for system index-based encryption with lazy client, SystemIndexManager, and plugin resolution.
     * 
     * @param clientSupplier supplier that provides the client when needed
     * @param systemIndexManagerSupplier supplier that provides the SystemIndexManager when needed
     * @param pluginSupplier supplier that provides the plugin instance for shared resolver access
     */
    public CryptoEngineFactory(
        Supplier<Client> clientSupplier,
        Supplier<SystemIndexManager> systemIndexManagerSupplier,
        Supplier<CryptoDirectoryPlugin> pluginSupplier
    ) {
        this.clientSupplier = Objects.requireNonNull(clientSupplier, "Client supplier cannot be null");
        this.systemIndexManagerSupplier = Objects.requireNonNull(systemIndexManagerSupplier, "SystemIndexManager supplier cannot be null");
        this.pluginSupplier = Objects.requireNonNull(pluginSupplier, "Plugin supplier cannot be null");
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
     * Create a KeyIvResolver for translog encryption using the shared resolver from plugin.
     * This ensures both directory and translog use the exact same resolver instance.
     */
    private KeyIvResolver createTranslogKeyIvResolver(EngineConfig config) throws IOException {
        // Use shared resolver from plugin to ensure consistency with directory operations
        logger
            .debug(
                "Using shared resolver from plugin for translog encryption for index: {}",
                config.getIndexSettings().getIndex().getUUID()
            );

        return pluginSupplier.get().getOrCreateSharedResolver(config.getIndexSettings());
    }

}
