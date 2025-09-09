/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.systemindex;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.common.lifecycle.AbstractLifecycleComponent;
import org.opensearch.transport.client.Client;

/**
 * Manages the crypto system index lifecycle as a LifecycleComponent.
 * 
 * This component ensures that the .opensearch-crypto-keys system index is created
 * early during OpenSearch startup, before any encryption operations begin.
 * 
 * Key responsibilities:
 * - Create system index during doStart() phase
 * - Handle race conditions and cluster coordination
 * - Provide readiness status for other components
 * - Manage system index health monitoring
 *
 * @opensearch.internal
 */
public class SystemIndexManager extends AbstractLifecycleComponent {

    private static final Logger logger = LogManager.getLogger(SystemIndexManager.class);

    private final Client client;

    // Track system index readiness
    private final AtomicBoolean systemIndexReady = new AtomicBoolean(false);

    // Track if system index creation has been attempted
    private volatile boolean creationAttempted = false;

    /**
     * Creates a new SystemIndexManager.
     *
     * @param client the OpenSearch client for system index operations
     * @throws IllegalArgumentException if client is null
     */
    public SystemIndexManager(Client client) {
        if (client == null) {
            throw new IllegalArgumentException("Client cannot be null");
        }
        this.client = client;
        logger.info("SystemIndexManager initialized");
    }

    /**
     * {@inheritDoc}
     * 
     * Creates the crypto system index during the start phase of OpenSearch startup.
     * This ensures the system index is available before any encryption operations begin.
     */
    @Override
    protected void doStart() {
        logger.info("Starting SystemIndexManager - creating crypto system index");

        try {
            createSystemIndexIfNeeded();
            systemIndexReady.set(true);
            logger.info("SystemIndexManager started successfully - crypto system index is ready");
        } catch (Exception e) {
            systemIndexReady.set(false);
            logger.error("Failed to start SystemIndexManager - crypto system index creation failed", e);
            // Don't throw exception to prevent OpenSearch startup failure
            // Components will check readiness and handle accordingly
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doStop() {
        logger.info("Stopping SystemIndexManager");
        systemIndexReady.set(false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void doClose() throws IOException {
        logger.info("Closing SystemIndexManager");
        systemIndexReady.set(false);
    }

    /**
     * Checks if the crypto system index is ready for operations.
     *
     * @return true if the system index is ready, false otherwise
     */
    public boolean isSystemIndexReady() {
        return systemIndexReady.get();
    }

    /**
     * Waits for the system index to become ready with timeout.
     *
     * @param timeoutMs maximum time to wait in milliseconds
     * @return true if system index became ready within timeout, false otherwise
     */
    public boolean waitForSystemIndexReady(long timeoutMs) {
        if (systemIndexReady.get()) {
            return true;
        }

        long startTime = System.currentTimeMillis();
        long endTime = startTime + timeoutMs;

        while (System.currentTimeMillis() < endTime) {
            if (systemIndexReady.get()) {
                logger.debug("System index became ready after {} ms", System.currentTimeMillis() - startTime);
                return true;
            }

            try {
                Thread.sleep(100); // Check every 100ms
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warn("Interrupted while waiting for system index readiness");
                return false;
            }
        }

        logger.warn("System index did not become ready within {} ms timeout", timeoutMs);
        return false;
    }

    /**
     * Forces a retry of system index creation.
     * This can be called by other components if they detect the system index is missing.
     *
     * @return true if creation succeeded or index already exists, false otherwise
     */
    public boolean retrySystemIndexCreation() {
        logger.info("Retrying crypto system index creation");

        try {
            createSystemIndexIfNeeded();
            systemIndexReady.set(true);
            logger.info("System index creation retry succeeded");
            return true;
        } catch (Exception e) {
            systemIndexReady.set(false);
            logger.error("System index creation retry failed", e);
            return false;
        }
    }

    /**
     * Creates the crypto system index if it doesn't already exist.
     * Handles race conditions where multiple nodes try to create the same index simultaneously.
     *
     * @throws IOException if index creation fails for reasons other than already exists
     */
    private void createSystemIndexIfNeeded() throws IOException {
        creationAttempted = true;

        try {
            // Check if index exists first
            IndicesExistsRequest existsRequest = new IndicesExistsRequest(CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME);
            IndicesExistsResponse existsResponse = client.admin().indices().exists(existsRequest).actionGet();

            if (existsResponse.isExists()) {
                logger.info("Crypto system index already exists: {}", CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME);
                return;
            }

            logger.info("Creating crypto system index: {}", CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME);

            try {
                // Create the system index with proper settings and mappings
                CreateIndexRequest createRequest = new CreateIndexRequest(CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME)
                    .settings(CryptoSystemIndexDescriptor.getSystemIndexSettings())
                    .mapping(CryptoSystemIndexDescriptor.getMappings());

                CreateIndexResponse createResponse = client.admin().indices().create(createRequest).actionGet();

                if (createResponse.isAcknowledged()) {
                    logger.info("Successfully created crypto system index: {}", CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME);
                } else {
                    throw new IOException("Failed to create crypto system index: not acknowledged");
                }

            } catch (ResourceAlreadyExistsException e) {
                // Race condition: another node created the index between our check and create attempt
                // This is expected behavior in cluster environments and should be treated as success
                logger
                    .info(
                        "Crypto system index already exists (created by another node): {}",
                        CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME
                    );
            }

        } catch (ResourceAlreadyExistsException e) {
            // Handle case where the exception wasn't caught in the inner try-catch
            logger
                .info(
                    "Crypto system index already exists (race condition resolved): {}",
                    CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME
                );
        } catch (Exception e) {
            logger.error("Failed to create crypto system index", e);
            throw new IOException("Failed to create crypto system index", e);
        }
    }

    /**
     * Gets the system index name managed by this component.
     *
     * @return the system index name
     */
    public String getSystemIndexName() {
        return CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME;
    }

    /**
     * Checks if system index creation has been attempted.
     *
     * @return true if creation was attempted, false otherwise
     */
    public boolean isCreationAttempted() {
        return creationAttempted;
    }
}
