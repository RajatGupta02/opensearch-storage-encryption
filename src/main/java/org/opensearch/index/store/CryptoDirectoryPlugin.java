/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.index.IndexModule;
import org.opensearch.index.IndexSettings;
import org.opensearch.index.engine.EngineFactory;
import org.opensearch.index.shard.IndexEventListener;
import org.opensearch.index.shard.IndexShard;
import org.opensearch.plugins.EnginePlugin;
import org.opensearch.plugins.IndexStorePlugin;
import org.opensearch.plugins.Plugin;

/**
 * A plugin that enables index level encryption and decryption.
 */
public class CryptoDirectoryPlugin extends Plugin implements IndexStorePlugin, EnginePlugin {

    private static final Logger LOGGER = LogManager.getLogger(CryptoDirectoryFactory.class);

    // Map to track running background threads per index UUID
    private final ConcurrentHashMap<String, Thread> backgroundThreads = new ConcurrentHashMap<>();

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

    @Override
    public void onIndexModule(IndexModule indexModule) {
        LOGGER.info("!!!!! testing that onIndexModule triggered for index: {} !!!!!", indexModule.getIndex().getName());

        // Add index event listener to handle shard lifecycle events
        indexModule.addIndexEventListener(new IndexEventListener() {
            @Override
            public void afterIndexShardCreated(IndexShard indexShard) {
                // Only start thread for primary shard 0 to ensure one per index across cluster
                ShardId shardId = indexShard.shardId();
                if (shardId.getId() == 0 && indexShard.routingEntry().primary()) {
                    LOGGER.info("Starting background thread for primary shard 0 of index: {}", shardId.getIndexName());
                    startBackgroundThread(indexShard.indexSettings().getIndex());
                }
            }

            @Override
            public void beforeIndexShardClosed(ShardId shardId, IndexShard indexShard, Settings indexSettings) {
                // Clean up when primary shard 0 is closed
                if (shardId.getId() == 0 && indexShard != null && indexShard.routingEntry().primary()) {
                    LOGGER.info("Stopping background thread for primary shard 0 of index: {}", shardId.getIndexName());
                    stopBackgroundThread(shardId.getIndex());
                }
            }
        });
    }

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
            return Optional.of(new CryptoEngineFactory());
        }
        return Optional.empty();
    }
}
