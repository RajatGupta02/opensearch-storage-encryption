/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.translog;

import java.io.IOException;
import java.util.function.LongConsumer;
import java.util.function.LongSupplier;

import org.opensearch.index.store.iv.KeyIvResolver;

/**
 * A Translog implementation that provides AES-CTR encryption capabilities.
 * 
 * This class extends LocalTranslog and overrides the getChannelFactory() method
 * to return a CryptoChannelFactory that creates FileChannels with transparent
 * encryption/decryption for translog files.
 *
 * Translog files (.tlog) are encrypted using AES-CTR with the same crypto
 * infrastructure as index files. Checkpoint files (.ckp) remain unencrypted
 * for performance and compatibility.
 *
 * Updated to use unified KeyIvResolver (same as index files) for consistent
 * key management across all encrypted components.
 *
 * @opensearch.internal
 */
public class CryptoTranslog extends LocalTranslog {

    private final KeyIvResolver keyIvResolver;
    private volatile CryptoChannelFactory cryptoChannelFactory;

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
        // super() must be the first statement
        super(config, translogUUID, deletionPolicy, globalCheckpointSupplier, primaryTermSupplier, persistedSequenceNumberConsumer);

        // Initialize crypto components after super() completes
        this.keyIvResolver = keyIvResolver;
        this.cryptoChannelFactory = new CryptoChannelFactory(keyIvResolver);

        logger.info("CryptoTranslog initialized with AES-CTR encryption for translog: {}", translogUUID);
    }

    /**
     * Override getChannelFactory to return our crypto-enabled channel factory.
     * This ensures that all translog file operations go through encrypted channels.
     * Uses lazy initialization to handle constructor ordering issues.
     *
     * @return the crypto channel factory
     */
    @Override
    public ChannelFactory getChannelFactory() {
        if (cryptoChannelFactory == null) {
            // Handle case where super() constructor calls this method before we finish initialization
            // This can happen during LocalTranslog constructor when it calls createWriter()
            synchronized (this) {
                if (cryptoChannelFactory == null && keyIvResolver != null) {
                    cryptoChannelFactory = new CryptoChannelFactory(keyIvResolver);
                }
            }
        }
        return cryptoChannelFactory != null ? cryptoChannelFactory : super.getChannelFactory();
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
