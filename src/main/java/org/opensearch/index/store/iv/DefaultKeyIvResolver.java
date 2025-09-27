/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.iv;

import java.io.IOException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.opensearch.common.Randomness;
import org.opensearch.common.crypto.DataKeyPair;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.index.store.cipher.AesCipherFactory;
import org.opensearch.index.store.kms.KmsCircuitBreakerException;
import org.opensearch.index.store.kms.KmsFailureClassifier;
import org.opensearch.index.store.kms.KmsFailureType;

/**
 * Default implementation of {@link KeyIvResolver} responsible for managing
 * the encryption key and initialization vector (IV) used in encrypting and decrypting
 * Lucene index files.
 *
 * Uses node-level cache for TTL-based key management with automatic refresh.
 * Provides component-aware behavior for INDEX vs TRANSLOG operations.
 *
 * Metadata files:
 * - "keyfile" stores the encrypted data key
 * - "ivFile" stores the base64-encoded IV
 *
 * @opensearch.internal
 */
public class DefaultKeyIvResolver implements KeyIvResolver {

    private static final Logger logger = LogManager.getLogger(DefaultKeyIvResolver.class);

    private final String indexUuid;
    private final Directory directory;
    private final MasterKeyProvider keyProvider;

    // Circuit breaker state for non-retryable KMS failures with 3-strike rule
    private volatile int revokeCounter = 0;
    private volatile boolean circuitBreakerActive = false;
    private volatile KmsFailureType failureType;
    private volatile boolean circuitBreakerLogged = false;

    // Fallback key for TRANSLOG operations during failures
    private volatile Key lastKnownKey;

    private String iv;

    private static final String IV_FILE = "ivFile";
    private static final String KEY_FILE = "keyfile";

    /**
     * Constructs a new {@link DefaultKeyIvResolver} and ensures the key and IV are initialized.
     *
     * @param indexUuid the unique identifier for the index
     * @param directory the Lucene directory to read/write metadata files
     * @param provider the JCE provider used for cipher operations
     * @param keyProvider the master key provider used to encrypt/decrypt data keys
     * @throws IOException if an I/O error occurs while reading or writing key/IV metadata
     */
    public DefaultKeyIvResolver(String indexUuid, Directory directory, Provider provider, MasterKeyProvider keyProvider)
        throws IOException {
        this.indexUuid = indexUuid;
        this.directory = directory;
        this.keyProvider = keyProvider;

        initialize();
    }

    /**
     * Attempts to load the IV from the directory.
     * If not present, it generates and persists new values.
     * Initializes cache with initial key load.
     */
    private void initialize() throws IOException {
        try {
            iv = readStringFile(IV_FILE);
            // Load initial key into cache
            try {
                Key initialKey = NodeLevelKeyCache.getInstance().get(indexUuid, this);
                lastKnownKey = initialKey;
            } catch (Exception e) {
                throw new IOException("Failed to load initial key from KMS", e);
            }
        } catch (java.nio.file.NoSuchFileException e) {
            initNewKeyAndIv();
        }
    }

    /**
     * Generates a new AES data key and IV (if not present), and writes them to metadata files.
     */
    private void initNewKeyAndIv() throws IOException {
        try {
            DataKeyPair pair = keyProvider.generateDataPair();
            writeByteArrayFile(KEY_FILE, pair.getEncryptedKey());

            byte[] ivBytes = new byte[AesCipherFactory.IV_ARRAY_LENGTH];
            SecureRandom random = Randomness.createSecure();
            random.nextBytes(ivBytes);
            iv = Base64.getEncoder().encodeToString(ivBytes);
            writeStringFile(IV_FILE, iv);

            // Load initial key into cache
            Key initialKey = NodeLevelKeyCache.getInstance().get(indexUuid, this);
            lastKnownKey = initialKey;
        } catch (Exception e) {
            throw new IOException("Failed to initialize new key and IV", e);
        }
    }

    /**
     * Reads a string value from the specified file in the directory.
     */
    private String readStringFile(String fileName) throws IOException {
        try (IndexInput in = directory.openInput(fileName, IOContext.READONCE)) {
            return in.readString();
        }
    }

    /**
     * Writes a string value to the specified file in the directory.
     */
    private void writeStringFile(String fileName, String value) throws IOException {
        try (IndexOutput out = directory.createOutput(fileName, IOContext.DEFAULT)) {
            out.writeString(value);
        }
    }

    /**
     * Reads a byte array from the specified file in the directory.
     */
    private byte[] readByteArrayFile(String fileName) throws IOException {
        try (IndexInput in = directory.openInput(fileName, IOContext.READONCE)) {
            int size = in.readInt();
            byte[] bytes = new byte[size];
            in.readBytes(bytes, 0, size);
            return bytes;
        }
    }

    /**
     * Writes a byte array to the specified file in the directory.
     */
    private void writeByteArrayFile(String fileName, byte[] data) throws IOException {
        try (IndexOutput out = directory.createOutput(fileName, IOContext.DEFAULT)) {
            out.writeInt(data.length);
            out.writeBytes(data, 0, data.length);
        }
    }

    /**
     * Loads key from KMS by decrypting the stored encrypted key.
     * This method is called by the node-level cache.
     * 
     * Implements graceful retry logic for accidental KMS key revocations:
     * - First refresh failure: Use existing key, increment counter (grace period)
     * - Second refresh failure: Activate circuit breaker and throw exception
     */
    Key loadKeyFromKMS() throws Exception {
        // Check circuit breaker first to avoid unnecessary KMS calls
        if (circuitBreakerActive) {
            logger.info("Circuit breaker active, failing fast without KMS call");
            throw new RuntimeException("KMS access failed persistently after 2 TTL cycles");
        }

        // Detect if this is a refresh operation vs initial load
        Key existingKey = NodeLevelKeyCache.getInstance().getIfPresent(indexUuid);
        boolean isRefreshOperation = (existingKey != null || lastKnownKey != null);

        try {
            // Attempt KMS decryption
            byte[] encryptedKey = readByteArrayFile(KEY_FILE);
            byte[] decryptedKey = keyProvider.decryptKey(encryptedKey);
            Key newKey = new SecretKeySpec(decryptedKey, "AES");

            // SUCCESS: Reset all failure state
            revokeCounter = 0;
            circuitBreakerActive = false;
            circuitBreakerLogged = false;
            lastKnownKey = newKey;

            logger.debug("Successfully {} key from KMS", isRefreshOperation ? "refreshed" : "loaded");

            return newKey;

        } catch (Exception e) {
            if (isRefreshOperation) {
                KmsFailureType failureType = KmsFailureClassifier.classify(e);

                if (!KmsFailureClassifier.isRetryable(failureType)) {
                    revokeCounter++;

                    if (revokeCounter == 1) {
                        // First failure: Grace period - return existing key, don't throw
                        logger.warn("KMS refresh failed (attempt 1/2): {}. Using cached key, will retry next TTL cycle.", e.getMessage());
                        return lastKnownKey;

                    } else {
                        // Second failure: Activate circuit breaker and throw
                        circuitBreakerActive = true;
                        this.failureType = failureType;

                        if (!circuitBreakerLogged) {
                            logger.error("KMS refresh failed for 2 consecutive TTL cycles: {}. Circuit breaker activated.", e.getMessage());
                            circuitBreakerLogged = true;
                        }

                        throw new RuntimeException("KMS access failed persistently after 2 TTL cycles", e);
                    }
                } else {
                    // Retryable error during refresh - use existing key
                    logger.warn("KMS refresh failed with retryable error: {}. Using cached key.", e.getMessage());
                    return lastKnownKey;
                }
            }

            // Initial load failure OR non-refresh operations: always propagate exception
            logger.error("KMS initial load failed: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     * Returns the data key using default behavior (INDEX component type) for backward compatibility.
     */
    @Override
    public Key getDataKey() {
        return getDataKey(ComponentType.INDEX);
    }

    /**
     * {@inheritDoc}
     * Returns the data key with component-specific behavior for KMS refresh.
     * INDEX operations can trigger KMS refresh and fail on circuit breaker activation.
     * TRANSLOG operations never fail and always get a key.
     */
    @Override
    public Key getDataKey(ComponentType componentType) {
        // Component-aware circuit breaker check
        // TRANSLOG operations must NEVER fail - they bypass circuit breaker completely
        if (circuitBreakerActive && componentType == ComponentType.INDEX) {
            logger.debug("Circuit breaker active, blocking INDEX operation");
            throw new KmsCircuitBreakerException(failureType);
        }

        try {
            // INDEX operations: use cache (triggers KMS refresh if needed)
            if (componentType == ComponentType.INDEX) {
                return NodeLevelKeyCache.getInstance().get(indexUuid, this);
            } else {
                // TRANSLOG operations: try cache first, fallback to lastKnownKey
                Key cachedKey = NodeLevelKeyCache.getInstance().getIfPresent(indexUuid);
                if (cachedKey != null) {
                    return cachedKey;
                } else if (lastKnownKey != null) {
                    logger.debug("Using expired key for translog operations (cache miss)");
                    return lastKnownKey;
                } else {
                    throw new RuntimeException("No key available for translog operations");
                }
            }
        } catch (Exception e) {
            // Cache loading failed - all retry logic is handled in loadKeyFromKMS
            // If we get here, it means the cache loader threw an exception after exhausting retries
            if (e instanceof RuntimeException && e.getMessage() != null && e.getMessage().contains("KMS access failed persistently")) {
                // This is a circuit breaker activation from the cache loader
                throw (RuntimeException) e;
            }

            // For other exceptions, try to use lastKnownKey as fallback
            if (lastKnownKey != null) {
                logger.warn("Cache access failed: {}. Using last known key for {} operations.", e.getMessage(), componentType);
                return lastKnownKey;
            } else {
                throw new RuntimeException("No fallback key available", e);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getIvBytes() {
        return Base64.getDecoder().decode(iv);
    }

    /**
     * Checks if the circuit breaker is currently active.
     * This is used by the CryptoEngine to block new indexing operations.
     * 
     * @return true if circuit breaker is active, false otherwise
     */
    public boolean isCircuitBreakerActive() {
        return circuitBreakerActive;
    }

}
