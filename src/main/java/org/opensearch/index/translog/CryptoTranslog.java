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
    private final String translogUUID;
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

        // CRITICAL SECURITY FIX: super() must be first, but we validate inputs first
        super(config, translogUUID, deletionPolicy, globalCheckpointSupplier, primaryTermSupplier, persistedSequenceNumberConsumer);

        // SECURITY: Strict validation - never allow null components
        if (keyIvResolver == null || translogUUID == null) {
            throw new IllegalStateException(
                "CRITICAL SECURITY ERROR: Cannot create CryptoTranslog without keyIvResolver and translogUUID. "
                    + "Required for translog encryption. keyIvResolver="
                    + keyIvResolver
                    + ", translogUUID="
                    + translogUUID
            );
        }

        // Initialize crypto components immediately after super() completes
        this.translogUUID = translogUUID;
        this.keyIvResolver = keyIvResolver;

        logger
            .error(
                "CRYPTO DEBUG: About to initialize CryptoChannelFactory - translogUUID={}, keyIvResolver={}",
                translogUUID,
                (keyIvResolver != null ? "AVAILABLE" : "NULL")
            );

        // CRITICAL: Initialize crypto channel factory immediately to prevent any race conditions
        try {
            this.cryptoChannelFactory = new CryptoChannelFactory(keyIvResolver, translogUUID);
            logger.error("CRYPTO DEBUG: CryptoChannelFactory initialized AFTER super() - SUCCESS");
        } catch (Exception e) {
            logger.error("CRYPTO DEBUG: FAILED to initialize CryptoChannelFactory: {}", e.getMessage(), e);
            throw new IOException(
                "CRITICAL SECURITY ERROR: Failed to initialize crypto channel factory for translog encryption. "
                    + "Cannot proceed without encryption!",
                e
            );
        }

        logger
            .error(
                "CRYPTO DEBUG: CryptoTranslog CONSTRUCTOR completed - translogUUID={}, keyIvResolver={}, cryptoChannelFactory={}, hashCode={}",
                translogUUID,
                (keyIvResolver != null ? "AVAILABLE" : "NULL"),
                (cryptoChannelFactory != null ? "INITIALIZED" : "NULL"),
                this.hashCode()
            );
        logger.info("CryptoTranslog initialized with AES-CTR encryption for translog: {}", translogUUID);
    }

    /**
     * Override getChannelFactory to return our crypto-enabled channel factory.
     * This ensures that all translog file operations go through encrypted channels.
     * Uses lazy initialization to handle constructor ordering issues.
     *
     * @return the crypto channel factory
     * @throws IllegalStateException if crypto channel factory cannot be initialized (SECURITY: never fall back to plain text)
     */
    @Override
    public ChannelFactory getChannelFactory() {
        // CRITICAL DEBUG: Log every call to getChannelFactory with stack trace
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        StringBuilder sb = new StringBuilder();
        for (int i = 1; i < Math.min(6, stackTrace.length); i++) {
            sb.append(stackTrace[i].toString()).append(" -> ");
        }

        logger
            .error(
                "CRYPTO DEBUG: getChannelFactory() called - cryptoChannelFactory={}, keyIvResolver={}, translogUUID={}, instanceHash={}, STACK={}",
                (cryptoChannelFactory != null ? "INITIALIZED" : "NULL"),
                (keyIvResolver != null ? "AVAILABLE" : "NULL"),
                translogUUID,
                this.hashCode(),
                sb.toString()
            );

        if (cryptoChannelFactory == null) {
            // Handle case where super() constructor calls this method before we finish initialization
            // This can happen during LocalTranslog constructor when it calls createWriter()
            synchronized (this) {
                if (cryptoChannelFactory == null) {
                    // CRITICAL DEBUG: Log initialization attempt
                    logger
                        .error(
                            "CRYPTO DEBUG: Attempting to initialize CryptoChannelFactory - keyIvResolver={}, translogUUID={}",
                            (keyIvResolver != null ? "AVAILABLE" : "NULL"),
                            translogUUID
                        );

                    if (keyIvResolver != null && translogUUID != null) {
                        try {
                            cryptoChannelFactory = new CryptoChannelFactory(keyIvResolver, translogUUID);
                            logger.error("CRYPTO DEBUG: CryptoChannelFactory initialized successfully");
                        } catch (Exception e) {
                            logger.error("CRYPTO DEBUG: FAILED to initialize CryptoChannelFactory: {}", e.getMessage(), e);
                            // SECURITY: Never fall back to plain text - fail fast!
                            throw new IllegalStateException(
                                "CRITICAL SECURITY ERROR: Failed to initialize crypto channel factory for translog encryption. "
                                    + "Cannot proceed with plain text translog operations!",
                                e
                            );
                        }
                    } else {
                        // SECURITY: Never fall back to plain text - fail fast!
                        logger
                            .error(
                                "CRYPTO DEBUG: MISSING REQUIRED COMPONENTS - keyIvResolver={}, translogUUID={}",
                                keyIvResolver,
                                translogUUID
                            );
                        throw new IllegalStateException(
                            "CRITICAL SECURITY ERROR: Cannot initialize crypto channel factory - missing keyIvResolver or translogUUID. "
                                + "Required for translog encryption. keyIvResolver="
                                + keyIvResolver
                                + ", translogUUID="
                                + translogUUID
                        );
                    }
                }
            }
        }

        // SECURITY: NEVER return super.getChannelFactory() - this would bypass encryption!
        if (cryptoChannelFactory == null) {
            throw new IllegalStateException(
                "CRITICAL SECURITY ERROR: CryptoChannelFactory is null after initialization attempt. "
                    + "Cannot proceed with unencrypted translog operations!"
            );
        }

        logger.error("CRYPTO DEBUG: Returning CryptoChannelFactory - encryption enabled");
        return cryptoChannelFactory;
    }

    /**
     * Override key translog operation methods to track actual usage
     */
    @Override
    public Location add(Operation operation) throws IOException {
        logger.error("CRYPTO DEBUG: CryptoTranslog.add() called - operation={}, instanceHash={}", operation.opType(), this.hashCode());
        return super.add(operation);
    }

    @Override
    public void rollGeneration() throws IOException {
        logger.error("CRYPTO DEBUG: CryptoTranslog.rollGeneration() called - instanceHash={}", this.hashCode());
        super.rollGeneration();
    }

    @Override
    public boolean syncNeeded() {
        boolean needed = super.syncNeeded();
        logger.error("CRYPTO DEBUG: CryptoTranslog.syncNeeded() called - needed={}, instanceHash={}", needed, this.hashCode());
        return needed;
    }

    @Override
    public void sync() throws IOException {
        logger.error("CRYPTO DEBUG: CryptoTranslog.sync() called - instanceHash={}", this.hashCode());
        super.sync();
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
