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

import com.amazonaws.AmazonServiceException;

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

    // Pre-emptive refresh at 80% of TTL to avoid blocking
    private static final double REFRESH_THRESHOLD = 0.8;

    // Circuit breaker state
    private enum CircuitState {
        CLOSED,           // Normal operation
        OPEN_TRANSIENT,   // Temporary failures - shorter recovery interval
        OPEN_PERMANENT    // Permanent failures - longer recovery interval
    }

    private volatile CircuitState circuitState = CircuitState.CLOSED;
    private volatile int consecutiveFailures = 0;
    private final AtomicReference<Long> lastRecoveryAttemptRef = new AtomicReference<>(0L);

    // Configuration from settings
    private final int circuitBreakerFailureThreshold;
    private final long permanentFailureRecoveryIntervalMs;
    private final long transientFailureRecoveryIntervalMs;

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

        // Read TTL from settings (default 5 minutes)
        int ttlSeconds = settings.getAsInt("index.store.kms.data_key_ttl_seconds", 300);
        this.ttlMillis = ttlSeconds * 1000L;

        // Read circuit breaker configuration from settings
        this.circuitBreakerFailureThreshold = settings.getAsInt("index.store.kms.circuit_breaker_failure_threshold", 3);
        this.permanentFailureRecoveryIntervalMs = settings.getAsInt("index.store.kms.permanent_failure_recovery_interval_ms", 300000);
        this.transientFailureRecoveryIntervalMs = settings.getAsInt("index.store.kms.transient_failure_recovery_interval_ms", 30000);

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
     * Returns the data key, using TTL-based refresh with circuit breaker protection.
     */
    @Override
    public Key getDataKey() {
        DataKeyHolder current = dataKeyRef.get();

        // Handle first-time initialization (should not happen after initialize())
        if (current == null) {
            return initializeDataKeyWithRetry();
        }

        // SECURITY RULE: Never return expired keys
        if (current.isExpired(ttlMillis)) {
            long expiredSeconds = (System.currentTimeMillis() - (current.getRefreshTime() + ttlMillis)) / 1000;
            String errorMsg = String
                .format(
                    "Data key expired %d seconds ago. KMS access required for refresh. Circuit state: %s",
                    expiredSeconds,
                    circuitState
                );
            throw new RuntimeException(errorMsg);
        }

        // Pre-emptive refresh with circuit breaker protection
        if (current.needsRefresh(ttlMillis, REFRESH_THRESHOLD)) {
            attemptRefreshWithCircuitBreaker();
        }

        return current.getDataKey();
    }

    /**
     * Initialize data key during first-time access with circuit breaker protection.
     */
    private Key initializeDataKeyWithRetry() {
        synchronized (this) {
            // Double-check after acquiring lock
            DataKeyHolder current = dataKeyRef.get();
            if (current != null) {
                return current.getDataKey();
            }

            try {
                byte[] encryptedKey = readByteArrayFile(KEY_FILE);
                byte[] decryptedKey = keyProvider.decryptKey(encryptedKey);
                Key newKey = new SecretKeySpec(decryptedKey, "AES");

                DataKeyHolder holder = new DataKeyHolder(newKey, System.currentTimeMillis());
                dataKeyRef.set(holder);
                resetCircuitBreaker(); // Successful operation
                logger.info("Successfully initialized data key from KMS");
                return newKey;
            } catch (Exception e) {
                handleKmsFailure(e);
                logger.error("Failed to initialize data key from KMS", e);
                throw new RuntimeException("Failed to initialize data key from KMS", e);
            }
        }
    }

    /**
     * Attempt refresh with circuit breaker protection.
     */
    private void attemptRefreshWithCircuitBreaker() {
        // Skip refresh if circuit is open and not time for recovery
        if (circuitState != CircuitState.CLOSED) {
            if (shouldAttemptRecovery()) {
                attemptSingleRecovery();
            }
            return;
        }

        // Normal refresh with circuit breaker protection
        if (refreshInProgress.compareAndSet(false, true)) {
            try {
                Key newKey = performKmsRefresh();

                // Success - update key and reset circuit
                DataKeyHolder newHolder = new DataKeyHolder(newKey, System.currentTimeMillis());
                dataKeyRef.set(newHolder);
                resetCircuitBreaker();
                logger.info("Successfully refreshed data key from KMS");

            } catch (Exception e) {
                handleKmsFailure(e);
                logger.warn("KMS refresh failed: {}", e.getMessage());
            } finally {
                refreshInProgress.set(false);
            }
        }
    }

    /**
     * Perform actual KMS refresh operation.
     */
    private Key performKmsRefresh() throws IOException {
        byte[] encryptedKey = readByteArrayFile(KEY_FILE);
        byte[] decryptedKey = keyProvider.decryptKey(encryptedKey);
        return new SecretKeySpec(decryptedKey, "AES");
    }

    /**
     * Check if circuit breaker recovery should be attempted.
     */
    private boolean shouldAttemptRecovery() {
        long now = System.currentTimeMillis();
        long lastAttempt = lastRecoveryAttemptRef.get();
        long recoveryInterval = (circuitState == CircuitState.OPEN_PERMANENT)
            ? permanentFailureRecoveryIntervalMs
            : transientFailureRecoveryIntervalMs;

        return (now - lastAttempt) > recoveryInterval;
    }

    /**
     * Attempt single recovery operation using compareAndSet to ensure only one thread attempts.
     */
    private void attemptSingleRecovery() {
        long now = System.currentTimeMillis();
        long expectedLastAttempt = lastRecoveryAttemptRef.get();

        // Ensure only one thread attempts recovery
        if (!lastRecoveryAttemptRef.compareAndSet(expectedLastAttempt, now)) {
            return; // Another thread is already attempting recovery
        }

        logger.info("Attempting circuit breaker recovery. State: {}, consecutive failures: {}", circuitState, consecutiveFailures);

        try {
            Key newKey = performKmsRefresh();

            // Success! Update key and close circuit
            DataKeyHolder newHolder = new DataKeyHolder(newKey, System.currentTimeMillis());
            dataKeyRef.set(newHolder);
            resetCircuitBreaker();
            logger.info("Circuit breaker recovery successful - KMS access restored");

        } catch (Exception e) {
            logger.warn("Circuit breaker recovery failed: {}", e.getMessage());
            updateCircuitState(e);
        }
    }

    /**
     * Handle KMS failure by updating circuit breaker state.
     */
    private void handleKmsFailure(Exception e) {
        consecutiveFailures++;
        updateCircuitState(e);
        logger.warn("KMS failure (consecutive: {}/{}): {}", consecutiveFailures, circuitBreakerFailureThreshold, e.getMessage());
    }

    /**
     * Update circuit breaker state based on failure type and threshold.
     */
    private void updateCircuitState(Exception e) {
        if (consecutiveFailures >= circuitBreakerFailureThreshold) {
            CircuitState newState = isPermanentFailure(e) ? CircuitState.OPEN_PERMANENT : CircuitState.OPEN_TRANSIENT;

            if (circuitState != newState) {
                logger.warn("Circuit breaker opened: {} (consecutive failures: {})", newState, consecutiveFailures);
                circuitState = newState;
            }
        }
    }

    /**
     * Reset circuit breaker after successful operation.
     */
    private void resetCircuitBreaker() {
        consecutiveFailures = 0;
        circuitState = CircuitState.CLOSED;
    }

    /**
     * Classify failure as permanent or transient using AWS error codes.
     */
    private boolean isPermanentFailure(Exception e) {
        // AWS KMS specific error classification using structured error codes
        if (e instanceof AmazonServiceException) {
            AmazonServiceException awsEx = (AmazonServiceException) e;
            String errorCode = awsEx.getErrorCode();

            // Permanent failures - use 5-minute recovery interval
            switch (errorCode) {
                case "AccessDenied":              // 403 - No permission to use key
                case "InvalidKeyId.NotFound":     // 400 - Key doesn't exist
                case "KMSInvalidStateException":  // 400 - Key disabled/deleted
                case "DisabledException":         // 400 - Key explicitly disabled
                case "KeyUnavailableException":   // 500 - Key permanently unavailable
                    logger
                        .warn(
                            "Permanent KMS failure - Code: {}, Status: {}, RequestId: {}",
                            errorCode,
                            awsEx.getStatusCode(),
                            awsEx.getRequestId()
                        );
                    return true;

                case "ThrottlingException":         // 400 - Rate limiting
                case "KMSInternalException":        // 500 - Internal AWS error
                case "DependencyTimeoutException":  // Network timeout
                case "ServiceUnavailableException": // 503 - Temporary unavailable
                    logger
                        .warn(
                            "Transient KMS failure - Code: {}, Status: {}, RequestId: {}",
                            errorCode,
                            awsEx.getStatusCode(),
                            awsEx.getRequestId()
                        );
                    return false;

                default:
                    // Unknown AWS error - classify by HTTP status code
                    int statusCode = awsEx.getStatusCode();
                    boolean isPermanent = statusCode >= 400 && statusCode < 500;
                    logger
                        .warn(
                            "Unknown AWS KMS error - Code: {}, Status: {}, RequestId: {}, Classified as: {}",
                            errorCode,
                            statusCode,
                            awsEx.getRequestId(),
                            isPermanent ? "permanent" : "transient"
                        );
                    return isPermanent;
            }
        }

        // Non-AWS exceptions: default to transient (conservative approach)
        logger.warn("Non-AWS KMS exception: {}", e.getClass().getSimpleName());
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getIvBytes() {
        return Base64.getDecoder().decode(iv);
    }

}
