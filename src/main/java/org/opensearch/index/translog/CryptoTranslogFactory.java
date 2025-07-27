/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import org.opensearch.index.IndexSettings;
import org.opensearch.index.seqno.RetentionLeases;
import org.opensearch.index.translog.CryptoTranslog;
import org.opensearch.index.translog.Translog;
import org.opensearch.index.translog.TranslogConfig;
import org.opensearch.index.translog.TranslogDeletionPolicy;
import org.opensearch.index.translog.TranslogFactory;
import org.opensearch.index.store.iv.KeyIvResolver;

import java.io.IOException;
import java.util.function.BooleanSupplier;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * A factory for creating crypto-enabled translogs that use unified key management.
 * This factory creates translog instances that use the same KeyIvResolver as index files
 * for consistent key management across all encrypted components.
 */
public class CryptoTranslogFactory implements TranslogFactory {

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
        // Create a crypto-enabled translog with unified key resolver
        return new CryptoTranslog(
            config,
            translogUUID,
            deletionPolicy,
            globalCheckpointSupplier,
            primaryTermSupplier,
            persistedSequenceNumberConsumer,
            keyIvResolver
        );
    }
}
