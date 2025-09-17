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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

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
import org.opensearch.index.store.kms.KmsHealthMonitor;

/**
 * Default implementation of {@link KeyIvResolver} responsible for managing
 * the encryption key and initialization vector (IV) used in encrypting and decrypting
 * Lucene index files.
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

    // Thread-safe TTL-based data key management
    private final AtomicReference<DataKeyHolder> dataKeyRef = new AtomicReference<>();
    private final AtomicBoolean refreshInProgress = new AtomicBoolean(false);

    // Circuit breaker state for non-retryable KMS failures
    private volatile boolean nonRetryableFailureDetected = false;
    private volatile KmsFailureType permanentFailureType;

    // Pre-emptive refresh at 80% of TTL to avoid blocking
    private static final double REFRESH_THRESHOLD = 0.8;

    private String iv;

    private static final String IV_FILE = "ivFile";
    private static final String KEY_FILE = "keyfile";

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
     * Data key is loaded synchronously during initialization.
     */
    private void initialize() throws IOException {
        try {
            iv = readStringFile(IV_FILE);

            Key dataKey = new SecretKeySpec(keyProvider.decryptKey(readByteArrayFile(KEY_FILE)), "AES");

            DataKeyHolder holder = new DataKeyHolder(dataKey, System.currentTimeMillis());
            dataKeyRef.set(holder);
        } catch (java.nio.file.NoSuchFileException e) {
            initNewKeyAndIv();
        }
    }

    /**
     * Generates a new AES data key and IV (if not present), and writes them to metadata files.
     */
    private void initNewKeyAndIv() throws IOException {
        DataKeyPair pair = keyProvider.generateDataPair();
        writeByteArrayFile(KEY_FILE, pair.getEncryptedKey());

        byte[] ivBytes = new byte[AesCipherFactory.IV_ARRAY_LENGTH];
        SecureRandom random = Randomness.createSecure();
        random.nextBytes(ivBytes);
        iv = Base64.getEncoder().encodeToString(ivBytes);
        writeStringFile(IV_FILE, iv);

        byte[] decryptedKey = keyProvider.decryptKey(pair.getEncryptedKey());
        Key dataKey = new SecretKeySpec(decryptedKey, "AES");

        DataKeyHolder holder = new DataKeyHolder(dataKey, System.currentTimeMillis());
        dataKeyRef.set(holder);
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
        if (nonRetryableFailureDetected && componentType == ComponentType.INDEX) {
            throw new RuntimeException("KMS access revoked due to previous " + permanentFailureType + " failure");
        }

        DataKeyHolder current = dataKeyRef.get();

        // Handle first-time initialization (should not happen after initialize())
        if (current == null) {
            synchronized (this) {
                // Double-check after acquiring lock
                current = dataKeyRef.get();
                if (current != null) {
                    return current.getDataKey();
                }

                try {
                    byte[] encryptedKey = readByteArrayFile(KEY_FILE);
                    byte[] decryptedKey = keyProvider.decryptKey(encryptedKey);
                    Key newKey = new SecretKeySpec(decryptedKey, "AES");

                    DataKeyHolder holder = new DataKeyHolder(newKey, System.currentTimeMillis());
                    dataKeyRef.set(holder);
                    logger.info("Successfully initialized data key from KMS");
                    return newKey;
                } catch (Exception e) {
                    logger.error("Failed to initialize data key from KMS", e);
                    throw new RuntimeException("Failed to initialize data key from KMS", e);
                }
            }
        }

        // Pre-emptive refresh - only INDEX operations can trigger this
        if (current.needsRefresh(ttlMillis, REFRESH_THRESHOLD)) {
            if (componentType == ComponentType.INDEX) {
                attemptPreemptiveRefresh();
                // Get updated reference after potential refresh
                current = dataKeyRef.get();
            }
            // TRANSLOG operations: do nothing, use current key
        }

        // Handle expiration with component-specific behavior
        if (current.isExpired(ttlMillis)) {
            return handleExpiredKey(current, componentType);
        }

        return current.getDataKey();
    }

    /**
     * Attempts pre-emptive refresh of the data key (only called by INDEX operations).
     */
    private void attemptPreemptiveRefresh() {
        if (refreshInProgress.compareAndSet(false, true)) {
            try {
                refreshKeyFromKMS();
                logger.debug("Successfully refreshed data key pre-emptively (triggered by index operations)");
            } catch (Exception e) {
                logger.warn("Pre-emptive data key refresh failed, will retry later", e);
            } finally {
                refreshInProgress.set(false);
            }
        }
    }

    /**
     * Handles expired key based on component type.
     */
    private Key handleExpiredKey(DataKeyHolder current, ComponentType componentType) {
        switch (componentType) {
            case INDEX:
                // Index operations: try refresh, handle failure based on type
                logger.debug("Data key expired for index operations, attempting KMS refresh");
                try {
                    return refreshKeyFromKMS();
                } catch (Exception e) {
                    // Classify failure type for appropriate handling
                    KmsFailureType failureType = KmsFailureClassifier.classify(e);

                    if (KmsFailureClassifier.isRetryable(failureType)) {
                        // Retryable failure: use existing key if available
                        if (current != null) {
                            logger.warn("KMS refresh failed (retryable): {}. Using expired key for index operations.", e.getMessage());
                            return current.getDataKey();
                        } else {
                            throw new RuntimeException("KMS refresh failed (retryable) and no existing key available", e);
                        }
                    } else {
                        // Non-retryable failure: circuit breaker already set in refreshKeyFromKMS, fail immediately
                        throw new RuntimeException("KMS key unavailable: " + e.getMessage(), e);
                    }
                }

            case TRANSLOG:
                // Translog operations: never fail, use expired key
                logger.warn("Using expired key for translog operations (KMS refresh not attempted)");
                return current.getDataKey();

            default:
                throw new IllegalArgumentException("Unknown component type: " + componentType);
        }
    }

    /**
     * Refreshes the data key from KMS and updates the shared reference.
     */
    private Key refreshKeyFromKMS() throws Exception {
        try {
            byte[] encryptedKey = readByteArrayFile(KEY_FILE);
            byte[] decryptedKey = keyProvider.decryptKey(encryptedKey);
            Key newKey = new SecretKeySpec(decryptedKey, "AES");

            // Atomic update of shared datakey reference
            DataKeyHolder newHolder = new DataKeyHolder(newKey, System.currentTimeMillis());
            dataKeyRef.set(newHolder);

            return newKey;

        } catch (Exception e) {
            // Classify KMS failure type
            KmsFailureType failureType = KmsFailureClassifier.classify(e);

            if (!KmsFailureClassifier.isRetryable(failureType)) {
                // Set circuit breaker for non-retryable failures
                nonRetryableFailureDetected = true;
                permanentFailureType = failureType;

                // Register with health monitor for automatic recovery
                KmsHealthMonitor.safeRegisterFailedResolver(this, failureType);

                logger.error("KMS key access failed (non-retryable): {}. Circuit breaker activated.", e.getMessage());
            } else {
                logger.warn("KMS refresh failed (retryable): {}. Will retry on next TTL cycle.", e.getMessage());
            }

            // Re-throw the original exception
            throw e;
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
     * Tests KMS connectivity without affecting normal operations.
     * This method is called by the KMS health monitor to test if KMS has recovered.
     * 
     * @throws Exception if KMS is still unavailable
     */
    public void testKmsConnectivity() throws Exception {
        // Test by attempting to decrypt the existing encrypted key
        byte[] encryptedKey = readByteArrayFile(KEY_FILE);
        keyProvider.decryptKey(encryptedKey);
        // If we reach here, KMS is accessible
    }

    /**
     * Resets the circuit breaker state, allowing KMS operations to resume.
     * This should only be called by the KMS health monitor after confirming KMS recovery.
     */
    public void resetCircuitBreaker() {
        if (nonRetryableFailureDetected) {
            nonRetryableFailureDetected = false;
            permanentFailureType = null;
            logger.info("Circuit breaker reset - KMS operations can resume");
        }
    }

    /**
     * Checks if the circuit breaker is currently active.
     * 
     * @return true if circuit breaker is active (KMS operations blocked)
     */
    public boolean isCircuitBreakerActive() {
        return nonRetryableFailureDetected;
    }

    /**
     * Gets the failure type that triggered the circuit breaker.
     * 
     * @return the failure type, or null if circuit breaker is not active
     */
    public KmsFailureType getCircuitBreakerFailureType() {
        return permanentFailureType;
    }

}
