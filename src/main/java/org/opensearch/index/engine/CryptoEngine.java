/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.engine;

import java.io.IOException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.engine.Engine.Delete;
import org.opensearch.index.engine.Engine.Index;
import org.opensearch.index.store.iv.DefaultKeyIvResolver;
import org.opensearch.index.store.iv.KeyIvResolver;
import org.opensearch.index.store.kms.KmsCircuitBreakerException;
import org.opensearch.index.store.kms.KmsFailureType;

/**
 * Custom engine implementation that blocks new indexing operations
 * when the KMS circuit breaker is active. This prevents data loss
 * by allowing in-flight operations to complete while blocking new ones.
 */
public class CryptoEngine extends InternalEngine {
    private static final Logger logger = LogManager.getLogger(CryptoEngine.class);

    private final KeyIvResolver keyIvResolver;

    public CryptoEngine(EngineConfig engineConfig, KeyIvResolver keyIvResolver) {
        super(engineConfig);
        this.keyIvResolver = keyIvResolver;
    }

    @Override
    public IndexResult index(Index index) throws IOException {
        // Check if circuit breaker is active for this index
        checkCircuitBreaker(index.id());

        // If circuit breaker is not active, proceed with normal indexing
        return super.index(index);
    }

    @Override
    public DeleteResult delete(Delete delete) throws IOException {
        // Check if circuit breaker is active for this index
        checkCircuitBreaker(delete.id());

        // If circuit breaker is not active, proceed with normal deletion
        return super.delete(delete);
    }

    /**
     * Checks if the circuit breaker is active for the current index.
     * If active, throws an exception to block the operation.
     * 
     * @param id The document ID being operated on (for logging)
     * @throws EngineException if the circuit breaker is active
     */
    private void checkCircuitBreaker(String id) throws EngineException {
        // Cast to DefaultKeyIvResolver to access isCircuitBreakerActive method
        if (keyIvResolver instanceof DefaultKeyIvResolver) {
            DefaultKeyIvResolver resolver = (DefaultKeyIvResolver) keyIvResolver;

            // Check if circuit breaker is active
            if (resolver.isCircuitBreakerActive()) {
                logger.warn("Blocking operation for document {} due to active circuit breaker for index {}", id, shardId.getIndexName());

                // Use a generic failure type for manual circuit breaker activation
                throw new EngineException(
                    shardId,
                    "Cannot index/delete document - KMS circuit breaker is active for index " + shardId.getIndexName(),
                    new KmsCircuitBreakerException(KmsFailureType.ACCESS_DENIED)
                );
            }
        }
    }
}
