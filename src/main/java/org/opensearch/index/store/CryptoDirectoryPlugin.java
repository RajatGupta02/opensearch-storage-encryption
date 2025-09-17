/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.index.IndexModule;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.store.kms.KmsHealthMonitor;
import org.opensearch.plugins.EnginePlugin;
import org.opensearch.plugins.IndexStorePlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

/**
 * A plugin that enables index level encryption and decryption.
 */
public class CryptoDirectoryPlugin extends Plugin implements IndexStorePlugin, EnginePlugin {

    private static final Logger LOGGER = LogManager.getLogger(CryptoDirectoryFactory.class);

    /**
     * The default constructor.
     */
    public CryptoDirectoryPlugin() {
        super();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<Setting<?>> getSettings() {
        return Arrays
            .asList(
                CryptoDirectoryFactory.INDEX_KMS_TYPE_SETTING,
                CryptoDirectoryFactory.INDEX_CRYPTO_PROVIDER_SETTING,
                CryptoDirectoryFactory.KMS_DATA_KEY_TTL_SECONDS_SETTING
            );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, DirectoryFactory> getDirectoryFactories() {
        return Collections.singletonMap("cryptofs", new CryptoDirectoryFactory());
    }

    /**
     * {@inheritDoc}
     * 
     * Initialize KMS Health Monitor during plugin startup to enable automatic
     * recovery from KMS failures.
     */
    @Override
    public Collection<Object> createComponents(
        Client client,
        ClusterService clusterService,
        ThreadPool threadPool,
        ResourceWatcherService resourceWatcherService,
        ScriptService scriptService,
        NamedXContentRegistry xContentRegistry,
        Environment environment,
        NodeEnvironment nodeEnvironment,
        NamedWriteableRegistry namedWriteableRegistry,
        IndexNameExpressionResolver indexNameExpressionResolver,
        Supplier<RepositoriesService> repositoriesServiceSupplier
    ) {

        // Initialize KMS Health Monitor singleton for automatic recovery from KMS failures
        try {
            KmsHealthMonitor.initialize(environment.settings(), threadPool, client, clusterService);
            LOGGER.info("KMS Health Monitor successfully initialized for automatic failure recovery");
        } catch (Exception e) {
            LOGGER.error("Failed to initialize KMS Health Monitor - automatic recovery will not be available", e);
            // Don't fail plugin startup, but log the issue
        }

        // No components need to be registered with the dependency injection framework
        return Collections.emptyList();
    }

    // @Override
    // public void onIndexModule(IndexModule indexModule) {
    // LOGGER.info("!!!!! onIndexModule triggered!!!!");
    // try {
    // Thread.sleep(5 * 60 * 1000);
    // } catch (InterruptedException e) {
    // e.printStackTrace();
    // }
    // }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<EngineFactory> getEngineFactory(IndexSettings indexSettings) {
        // Only provide our custom engine factory for cryptofs indices
        if ("cryptofs".equals(indexSettings.getValue(IndexModule.INDEX_STORE_TYPE_SETTING))) {
            return Optional.of(new CryptoEngineFactory());
        }
        return Optional.empty();
    }
}
