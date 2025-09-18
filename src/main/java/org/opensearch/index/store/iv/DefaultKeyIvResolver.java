/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.iv;

import java.io.IOException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.time.Duration;
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
import org.opensearch.common.settings.Settings;
import org.opensearch.index.store.cipher.AesCipherFactory;
import org.opensearch.index.store.kms.KmsFailureClassifier;
import org.opensearch.index.store.kms.KmsFailureType;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;

/**
 * Default implementation of {@link KeyIvResolver} responsible for managing
 * the encryption key and initialization vector (IV) used in encrypting and decrypting
 * Lucene index files.
 *
 * Uses Caffeine cache for TTL-based key management with automatic refresh.
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

    private final Directory directory;
    private final MasterKeyProvider keyProvider;
    private final long ttlMillis;

    // Caffeine cache for TTL-based key management
    private final LoadingCache<String, Key> keyCache;

    // Circuit breaker state for non-retryable KMS failures
    private volatile boolean circuitBreakerActive = false;
    private volatile KmsFailureType failureType;

    // Fallback key for TRANSLOG operations during failures
    private volatile Key lastKnownKey;

    private String iv;

    private static final String IV_FILE = "ivFile";
    private static final String KEY_FILE = "keyfile";
    private static final String CACHE_KEY = "DATA_KEY";

    /**
     * Constructs a new {@link DefaultKeyIvResolver} and ensures the key and IV are initialized.
     *
     * @param directory the Lucene directory to read/write metadata files
     * @param provider the JCE provider used for cipher operations
     * @param keyProvider the master key provider used to encrypt/decrypt data keys
     * @param settings the settings containing TTL configuration
     * @throws IOException if an I/O error occurs while reading or writing key/IV metadata
     */
    public DefaultKeyIvResolver(Directory directory, Provider provider, MasterKeyProvider keyProvider, Settings settings)
        throws IOException {
        this.directory = directory;
        this.keyProvider = keyProvider;

        // Read TTL from settings (default 1 hour)
        int ttlSeconds = settings.getAsInt("index.store.kms.data_key_ttl_seconds", 3600);
        this.ttlMillis = ttlSeconds * 1000L;

        // Initialize Caffeine cache with TTL and pre-emptive refresh
        this.keyCache = Caffeine
            .newBuilder()
            .expireAfterWrite(Duration.ofMillis(ttlMillis))
            .refreshAfterWrite(Duration.ofMillis((long) (ttlMillis * 0.8))) // 80% refresh threshold
            .build(this::loadKeyFromKMS);

        initialize();
    }

    /**
     * Constructs a new {@link DefaultKeyIvResolver} with default TTL settings.
     * This constructor is kept for backward compatibility.
     *
     * @param directory the Lucene directory to read/write metadata files
     * @param provider the JCE provider used for cipher operations
     * @param keyProvider the master key provider used to encrypt/decrypt data keys
     * @throws IOException if an I/O error occurs while reading or writing key/IV metadata
     */
    public DefaultKeyIvResolver(Directory directory, Provider provider, MasterKeyProvider keyProvider) throws IOException {
        this(directory, provider, keyProvider, Settings.EMPTY);
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
                Key initialKey = loadKeyFromKMS(CACHE_KEY);
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
            Key initialKey = loadKeyFromKMS(CACHE_KEY);
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
     * Cache loader method for Caffeine cache.
     * Loads key from KMS by decrypting the stored encrypted key.
     */
    private Key loadKeyFromKMS(String keyId) throws Exception {
        byte[] encryptedKey = readByteArrayFile(KEY_FILE);
        byte[] decryptedKey = keyProvider.decryptKey(encryptedKey);
        Key newKey = new SecretKeySpec(decryptedKey, "AES");

        // Update lastKnownKey for fallback
        lastKnownKey = newKey;

        return newKey;
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
     * INDEX operations can trigger KMS refresh and fail on unavailability.
     * TRANSLOG operations never trigger KMS refresh and never fail.
     */
    @Override
    public Key getDataKey(ComponentType componentType) {
        // Component-aware circuit breaker check
        // TRANSLOG operations must NEVER fail - they bypass circuit breaker completely
        if (circuitBreakerActive && componentType == ComponentType.INDEX) {
            throw new RuntimeException("KMS access revoked due to previous " + failureType + " failure");
        }

        try {
            // INDEX operations: use cache (triggers KMS if needed)
            if (componentType == ComponentType.INDEX) {
                return keyCache.get(CACHE_KEY);
            } else {
                // TRANSLOG operations: try cache first, fallback to lastKnownKey
                Key cachedKey = keyCache.getIfPresent(CACHE_KEY);
                if (cachedKey != null) {
                    return cachedKey;
                } else if (lastKnownKey != null) {
                    logger.warn("Using expired key for translog operations (cache miss)");
                    return lastKnownKey;
                } else {
                    // Should not happen after initialization
                    throw new RuntimeException("No key available for translog operations");
                }
            }
        } catch (Exception e) {
            return handleCacheFailure(e, componentType);
        }
    }

    /**
     * Handles cache loading failures with component-aware behavior.
     */
    private Key handleCacheFailure(Exception e, ComponentType componentType) {
        KmsFailureType failureType = KmsFailureClassifier.classify(e);

        if (!KmsFailureClassifier.isRetryable(failureType) && componentType == ComponentType.INDEX) {
            // Non-retryable failure for INDEX: activate circuit breaker
            circuitBreakerActive = true;
            this.failureType = failureType;
            logger.error("KMS key access failed (non-retryable): {}. Circuit breaker activated.", e.getMessage());
            throw new RuntimeException("KMS key unavailable: " + failureType, e);
        }

        // Retryable failure OR TRANSLOG operation: use last known key
        if (lastKnownKey != null) {
            logger.warn("KMS refresh failed ({}): {}. Using last known key for {} operations.", failureType, e.getMessage(), componentType);
            return lastKnownKey;
        } else {
            throw new RuntimeException("No fallback key available", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getIvBytes() {
        return Base64.getDecoder().decode(iv);
    }

}
