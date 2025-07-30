/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.util.function.BooleanSupplier;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.iv.KeyIvResolver;

/**
 * A factory for creating crypto-enabled translogs that use unified key management.
 * This factory creates translog instances that use the same KeyIvResolver as index files
 * for consistent key management across all encrypted components.
 */
public class CryptoTranslogFactory implements TranslogFactory {

    private static final Logger logger = LogManager.getLogger(CryptoTranslogFactory.class);

    private final KeyIvResolver keyIvResolver;

    /**
     * Constructor for CryptoTranslogFactory.
     *
     * @param keyIvResolver the unified key/IV resolver (same as used by index files)
     */
    public CryptoTranslogFactory(KeyIvResolver keyIvResolver) {
        this.keyIvResolver = keyIvResolver;
    }

    @Override
    public Translog newTranslog(
        TranslogConfig config,
        String translogUUID,
        TranslogDeletionPolicy deletionPolicy,
        LongSupplier globalCheckpointSupplier,
        LongSupplier primaryTermSupplier,
        LongConsumer persistedSequenceNumberConsumer,
        BooleanSupplier startedPrimarySupplier
    ) throws IOException {
        // CRITICAL DEBUG: Log translog creation
        logger
            .error(
                "CRYPTO DEBUG: CryptoTranslogFactory.newTranslog() called - translogUUID={}, configPath={}, factoryHashCode={}",
                translogUUID,
                config.getTranslogPath(),
                this.hashCode()
            );

        // Create a crypto-enabled translog with unified key resolver using static factory method
        CryptoTranslog cryptoTranslog = new CryptoTranslog(
                config,
                translogUUID,
                deletionPolicy,
                globalCheckpointSupplier,
                primaryTermSupplier,
                persistedSequenceNumberConsumer,
                keyIvResolver
            );

        logger.error("CRYPTO DEBUG: CryptoTranslogFactory created CryptoTranslog instance - hashCode={}", cryptoTranslog.hashCode());
        return cryptoTranslog;
    }
}
