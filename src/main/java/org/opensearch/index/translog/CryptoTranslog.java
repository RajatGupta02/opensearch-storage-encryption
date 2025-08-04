/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.store.iv.KeyIvResolver;

/**
 * A Translog implementation that provides AES-CTR encryption capabilities.
 * 
 * This class extends LocalTranslog and injects a CryptoChannelFactory during construction
 * to ensure that all translog file operations go through encrypted channels.
 *
 * Translog files (.tlog) are encrypted using AES-CTR with the same crypto
 * infrastructure as index files. Checkpoint files (.ckp) remain unencrypted
 * for performance and compatibility.
 *
 * Uses unified KeyIvResolver (same as index files) for consistent
 * key management across all encrypted components.
 *
 * @opensearch.internal
 */
public class CryptoTranslog extends LocalTranslog {

    private static final Logger logger = LogManager.getLogger(CryptoTranslog.class);

    private final KeyIvResolver keyIvResolver;
    private final String translogUUID;

    /**
     * Creates a new CryptoTranslog with AES-CTR encryption.
     *
     * @param config the translog configuration
     * @param translogUUID the translog UUID
     * @param deletionPolicy the deletion policy
     * @param globalCheckpointSupplier the global checkpoint supplier
     * @param primaryTermSupplier the primary term supplier
     * @param persistedSequenceNumberConsumer the persisted sequence number consumer
     * @param keyIvResolver the key and IV resolver for encryption (unified with index files)
     * @throws IOException if translog creation fails
     */
    public CryptoTranslog(
        TranslogConfig config,
        String translogUUID,
        TranslogDeletionPolicy deletionPolicy,
        LongSupplier globalCheckpointSupplier,
        LongSupplier primaryTermSupplier,
        LongConsumer persistedSequenceNumberConsumer,
        KeyIvResolver keyIvResolver
    )
        throws IOException {

        super(
            config,
            translogUUID,
            deletionPolicy,
            globalCheckpointSupplier,
            primaryTermSupplier,
            persistedSequenceNumberConsumer,
            createCryptoChannelFactory(keyIvResolver, translogUUID)
        );

        // SECURITY: Strict validation after super() - never allow null components
        if (keyIvResolver == null || translogUUID == null) {
            throw new IllegalArgumentException(
                "CRITICAL SECURITY ERROR: Cannot create CryptoTranslog without keyIvResolver and translogUUID. "
                    + "Required for translog encryption. keyIvResolver="
                    + keyIvResolver
                    + ", translogUUID="
                    + translogUUID
            );
        }

        // Initialize instance fields
        this.keyIvResolver = keyIvResolver;
        this.translogUUID = translogUUID;

        logger.info("CryptoTranslog initialized with AES-CTR encryption for translog: {}", translogUUID);
    }

    /**
     * Helper method to create CryptoChannelFactory for constructor use.
     * This is needed because Java requires super() to be the first statement.
     * Returns ChannelFactory interface type to match LocalTranslog constructor signature.
     */
    private static ChannelFactory createCryptoChannelFactory(KeyIvResolver keyIvResolver, String translogUUID) throws IOException {
        try {
            CryptoChannelFactory channelFactory = new CryptoChannelFactory(keyIvResolver, translogUUID);
            LogManager.getLogger(CryptoTranslog.class).debug("CryptoChannelFactory initialized for translog: {}", translogUUID);
            return channelFactory; // CryptoChannelFactory implements ChannelFactory
        } catch (Exception e) {
            LogManager
                .getLogger(CryptoTranslog.class)
                .error("CRITICAL SECURITY ERROR: Failed to initialize CryptoChannelFactory: {}", e.getMessage(), e);
            throw new IOException(
                "CRITICAL SECURITY ERROR: Failed to initialize crypto channel factory for translog encryption. "
                    + "Cannot proceed without encryption!",
                e
            );
        }
    }

    /**
     * Gets the key IV resolver used for encryption.
     *
     * @return the key IV resolver
     */
    public KeyIvResolver getKeyIvResolver() {
        return keyIvResolver;
    }

    /**
     * Ensure proper cleanup of crypto resources.
     */
    @Override
    public void close() throws IOException {
        try {
            super.close();
        } finally {
            logger.debug("CryptoTranslog closed - encrypted translog files");
        }
    }
}
