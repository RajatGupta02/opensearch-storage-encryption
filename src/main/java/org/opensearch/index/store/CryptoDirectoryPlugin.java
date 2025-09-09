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
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.index.IndexModule;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.store.systemindex.CryptoSystemIndexDescriptor;
import org.opensearch.index.store.systemindex.SystemIndexManager;
import org.opensearch.indices.SystemIndexDescriptor;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.EnginePlugin;
import org.opensearch.plugins.IndexStorePlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.SystemIndexPlugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

/**
 * A plugin that enables index level encryption and decryption.
 */
public class CryptoDirectoryPlugin extends Plugin implements IndexStorePlugin, EnginePlugin, SystemIndexPlugin, ClusterPlugin {

    private static final Logger LOGGER = LogManager.getLogger(CryptoDirectoryFactory.class);

    // Map to track running background threads per index UUID
    private final ConcurrentHashMap<String, Thread> backgroundThreads = new ConcurrentHashMap<>();

    // Dependencies injected via createComponents
    private Client client;
    private SystemIndexManager systemIndexManager;

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
                CryptoDirectoryFactory.INDEX_KMS_KEY_ID_SETTING,
                CryptoDirectoryFactory.INDEX_CRYPTO_PROVIDER_SETTING,
                CryptoDirectoryFactory.KMS_DATA_KEY_TTL_SECONDS_SETTING
            );
    }

    /**
     * {@inheritDoc}
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
        this.client = client;

        // Create SystemIndexManager to handle early system index creation
        this.systemIndexManager = new SystemIndexManager(client);

        // Return SystemIndexManager as a LifecycleComponent for OpenSearch to manage
        return Arrays.asList(systemIndexManager);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, DirectoryFactory> getDirectoryFactories() {
        return Collections.singletonMap("cryptofs", new CryptoDirectoryFactory(() -> this.client, () -> this.systemIndexManager));
    }

    // @Override
    // public void onIndexModule(IndexModule indexModule) {
    // LOGGER.info("CryptoDirectoryPlugin triggered for index: {}", indexModule.getIndex().getName());

    // // Only handle cryptofs indices - check if this index uses cryptofs store type
    // Settings indexSettings = indexModule.getSettings();
    // String storeType = indexSettings.get(IndexModule.INDEX_STORE_TYPE_SETTING.getKey());
    // if (!"cryptofs".equals(storeType)) {
    // return;
    // }

    // // Add index event listener to handle crypto lifecycle events
    // indexModule.addIndexEventListener(new IndexEventListener() {
    // @Override
    // public void afterIndexShardCreated(IndexShard indexShard) {
    // ShardId shardId = indexShard.shardId();

    // // Only handle primary shard 0 to ensure one operation per index across cluster
    // if (shardId.getId() == 0 && indexShard.routingEntry().primary()) {
    // LOGGER.info("Initializing crypto for primary shard 0 of index: {}", shardId.getIndexName());

    // // Note: System index creation and key management is handled lazily by SystemIndexKeyIvResolver
    // // when the first encryption operation occurs

    // // Start background monitoring thread for this index
    // startBackgroundThread(indexShard.indexSettings().getIndex());
    // }
    // }

    // @Override
    // public void beforeIndexShardClosed(ShardId shardId, IndexShard indexShard, Settings indexSettings) {
    // // Clean up when primary shard 0 is closed
    // if (shardId.getId() == 0 && indexShard != null && indexShard.routingEntry().primary()) {
    // LOGGER.info("Cleaning up crypto resources for primary shard 0 of index: {}", shardId.getIndexName());
    // stopBackgroundThread(shardId.getIndex());
    // }
    // }
    // });
    // }

    /**
     * Start background thread for the given index that prints "hello world" every 10 seconds
     */
    private void startBackgroundThread(org.opensearch.core.index.Index index) {
        String indexKey = index.getUUID();

        Thread backgroundThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(10000); // 10 seconds
                    LOGGER
                        .info(
                            "hello world from index: {} (UUID: {}) - Thread ID: {}",
                            index.getName(),
                            index.getUUID(),
                            Thread.currentThread().threadId()
                        );
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LOGGER.info("Background thread interrupted for index: {}", index.getName());
                    break;
                }
            }
        });

        backgroundThread.setDaemon(true);
        backgroundThread.setName("CryptoPlugin-HelloWorld-" + index.getName());
        backgroundThread.start();

        // Store the thread in our tracking map
        backgroundThreads.put(indexKey, backgroundThread);
        LOGGER.info("Started background thread for index: {} with thread ID: {}", index.getName(), backgroundThread.threadId());
    }

    /**
     * Stop background thread for the given index
     */
    private void stopBackgroundThread(org.opensearch.core.index.Index index) {
        String indexKey = index.getUUID();
        Thread thread = backgroundThreads.remove(indexKey);

        if (thread != null) {
            thread.interrupt();
            LOGGER.info("Stopped background thread for index: {}", index.getName());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<EngineFactory> getEngineFactory(IndexSettings indexSettings) {
        // Only provide our custom engine factory for cryptofs indices
        if ("cryptofs".equals(indexSettings.getValue(IndexModule.INDEX_STORE_TYPE_SETTING))) {
            return Optional.of(new CryptoEngineFactory(() -> this.client, () -> this.systemIndexManager));
        }
        return Optional.empty();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<SystemIndexDescriptor> getSystemIndexDescriptors(Settings settings) {
        return Collections.singletonList(CryptoSystemIndexDescriptor.getDescriptor());
    }

    /**
     * {@inheritDoc}
     * 
     * Called when the node has started and joined the cluster. This is the appropriate
     * time to create the crypto system index, as the cluster service is now ready.
     */
    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        if (systemIndexManager != null) {
            LOGGER.info("Node started - initializing crypto system index");

            // Initialize system index now that cluster is ready
            boolean success = systemIndexManager.initializeSystemIndex();

            if (success) {
                LOGGER.info("Crypto system index initialization completed successfully");
            } else {
                LOGGER.warn("Crypto system index initialization failed - encryption operations may fail until index is created");
            }
        } else {
            LOGGER.warn("SystemIndexManager not available during node startup - this should not happen");
        }
    }
}
