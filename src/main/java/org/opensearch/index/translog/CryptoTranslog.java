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

    private static final Logger logger = LogManager.getLogger(CryptoTranslog.class);

    private final KeyIvResolver keyIvResolver;
    private final String translogUUID;
    private volatile CryptoChannelFactory cryptoChannelFactory;

    // CONSTRUCTOR PARAMETERS: Store these to handle race condition during super() call
    private static final ThreadLocal<KeyIvResolver> CONSTRUCTOR_KEY_IV_RESOLVER = new ThreadLocal<>();
    private static final ThreadLocal<String> CONSTRUCTOR_TRANSLOG_UUID = new ThreadLocal<>();

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
    /**
     * Static factory method to create CryptoTranslog with proper ThreadLocal setup
     */
    public static CryptoTranslog create(
        TranslogConfig config,
        String translogUUID,
        TranslogDeletionPolicy deletionPolicy,
        LongSupplier globalCheckpointSupplier,
        LongSupplier primaryTermSupplier,
        LongConsumer persistedSequenceNumberConsumer,
        KeyIvResolver keyIvResolver
    ) throws IOException {

        // SECURITY: Strict validation - never allow null components
        if (keyIvResolver == null || translogUUID == null) {
            throw new IllegalArgumentException(
                "CRITICAL SECURITY ERROR: Cannot create CryptoTranslog without keyIvResolver and translogUUID. "
                    + "Required for translog encryption. keyIvResolver="
                    + keyIvResolver
                    + ", translogUUID="
                    + translogUUID
            );
        }

        // Store parameters in ThreadLocal so getChannelFactory() can access them during constructor
        CONSTRUCTOR_KEY_IV_RESOLVER.set(keyIvResolver);
        CONSTRUCTOR_TRANSLOG_UUID.set(translogUUID);

        logger
            .error(
                "CRYPTO DEBUG: Static factory method - ThreadLocal values set - keyIvResolver={}, translogUUID={}",
                (keyIvResolver != null ? "AVAILABLE" : "NULL"),
                translogUUID
            );

        // CRITICAL: Don't clean up ThreadLocal here - constructor needs them during super() call
        // Cleanup happens at the end of constructor instead
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

        // CRITICAL: super() must be first - getChannelFactory() will use ThreadLocal if needed
        super(config, translogUUID, deletionPolicy, globalCheckpointSupplier, primaryTermSupplier, persistedSequenceNumberConsumer);

        // Initialize instance fields after super() completes
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

        // CRITICAL: Clean up ThreadLocal to prevent memory leaks after constructor completes
        try {
            CONSTRUCTOR_KEY_IV_RESOLVER.remove();
            CONSTRUCTOR_TRANSLOG_UUID.remove();
            logger.error("CRYPTO DEBUG: ThreadLocal values cleaned up in constructor");
        } catch (Exception e) {
            logger.error("CRYPTO DEBUG: Error cleaning up ThreadLocal: {}", e.getMessage());
        }
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

        System.err.println("🚨🚨🚨 CRYPTO CRITICAL: getChannelFactory() METHOD CALLED 🚨🚨🚨");
        System.err.flush();

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

                    // Check if instance fields are available, otherwise use ThreadLocal (constructor race condition)
                    KeyIvResolver resolverToUse = keyIvResolver;
                    String uuidToUse = translogUUID;

                    if (resolverToUse == null || uuidToUse == null) {
                        // CONSTRUCTOR RACE CONDITION: Use ThreadLocal values set by static factory method
                        resolverToUse = CONSTRUCTOR_KEY_IV_RESOLVER.get();
                        uuidToUse = CONSTRUCTOR_TRANSLOG_UUID.get();

                        logger
                            .error(
                                "CRYPTO DEBUG: Using ThreadLocal values - keyIvResolver={}, translogUUID={}",
                                (resolverToUse != null ? "AVAILABLE" : "NULL"),
                                uuidToUse
                            );
                    }

                    if (resolverToUse != null && uuidToUse != null) {
                        try {
                            cryptoChannelFactory = new CryptoChannelFactory(resolverToUse, uuidToUse);
                            logger.error("CRYPTO DEBUG: CryptoChannelFactory initialized successfully during constructor race condition");
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
                                "CRYPTO DEBUG: MISSING REQUIRED COMPONENTS - keyIvResolver={}, translogUUID={}, ThreadLocal keyIvResolver={}, ThreadLocal translogUUID={}",
                                keyIvResolver,
                                translogUUID,
                                CONSTRUCTOR_KEY_IV_RESOLVER.get(),
                                CONSTRUCTOR_TRANSLOG_UUID.get()
                            );
                        throw new IllegalStateException(
                            "CRITICAL SECURITY ERROR: Cannot initialize crypto channel factory - missing keyIvResolver or translogUUID. "
                                + "Required for translog encryption. keyIvResolver="
                                + keyIvResolver
                                + ", translogUUID="
                                + translogUUID
                                + ", ThreadLocal keyIvResolver="
                                + CONSTRUCTOR_KEY_IV_RESOLVER.get()
                                + ", ThreadLocal translogUUID="
                                + CONSTRUCTOR_TRANSLOG_UUID.get()
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
     * Override createWriter to ensure crypto channel factory is used.
     * This fixes the issue where getChannelFactory() wasn't being called during constructor.
     */
    @Override
    TranslogWriter createWriter(long fileGeneration) throws IOException {
        logger.error("CRYPTO DEBUG: CryptoTranslog.createWriter(fileGeneration={}) called", fileGeneration);
        return createWriter(fileGeneration, getMinFileGeneration(), globalCheckpointSupplier.getAsLong(), persistedSequenceNumberConsumer);
    }

    /**
     * Override createWriter to ensure crypto channel factory is used directly.
     * This bypasses the getChannelFactory() method call during super() constructor.
     */
    @Override
    TranslogWriter createWriter(
        long fileGeneration,
        long initialMinTranslogGen,
        long initialGlobalCheckpoint,
        LongConsumer persistedSequenceNumberConsumer
    ) throws IOException {
        logger
            .error(
                "CRYPTO DEBUG: CryptoTranslog.createWriter(gen={}, minGen={}, checkpoint={}) called",
                fileGeneration,
                initialMinTranslogGen,
                initialGlobalCheckpoint
            );

        // Ensure crypto channel factory is available
        ChannelFactory channelFactory = getChannelFactory();

        logger.error("CRYPTO DEBUG: Using channelFactory={} for createWriter", channelFactory.getClass().getSimpleName());

        final TranslogWriter newWriter;
        try {
            newWriter = TranslogWriter
                .create(
                    shardId,
                    translogUUID,
                    fileGeneration,
                    location.resolve(getFilename(fileGeneration)),
                    channelFactory, // Use our crypto channel factory directly
                    config.getBufferSize(),
                    initialMinTranslogGen,
                    initialGlobalCheckpoint,
                    globalCheckpointSupplier,
                    this::getMinFileGeneration,
                    primaryTermSupplier.getAsLong(),
                    tragedy,
                    persistedSequenceNumberConsumer,
                    bigArrays,
                    indexSettings.isAssignedOnRemoteNode()
                );

            logger.error("CRYPTO DEBUG: Successfully created TranslogWriter with crypto channels for generation {}", fileGeneration);

        } catch (final IOException e) {
            logger.error("CRYPTO DEBUG: Failed to create TranslogWriter with crypto channels: {}", e.getMessage(), e);
            throw new TranslogException(shardId, "failed to create new translog file with encryption", e);
        }
        return newWriter;
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
