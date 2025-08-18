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
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
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

    // Background recovery thread for proactive KMS recovery
    private volatile ScheduledExecutorService backgroundRecoveryExecutor;
    private final AtomicBoolean backgroundRecoveryStarted = new AtomicBoolean(false);

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

        if (current.isExpired(ttlMillis) && circuitState == CircuitState.CLOSED) {
            synchronized (this) {
                // Double-check after acquiring lock
                current = dataKeyRef.get();
                if (current != null && current.isExpired(ttlMillis)) {
                    logger.warn("Data key expired with circuit CLOSED - attempting emergency refresh");
                    try {
                        Key newKey = performKmsRefresh();
                        DataKeyHolder newHolder = new DataKeyHolder(newKey, System.currentTimeMillis());
                        dataKeyRef.set(newHolder);
                        resetCircuitBreaker();
                        logger.info("Emergency refresh successful - key recovered");
                        return newKey;
                    } catch (Exception e) {
                        handleKmsFailure(e);
                        logger.error("Emergency refresh failed", e);
                        // Fall through to throw exception below
                    }
                }
            }
        }

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

                // Start background recovery thread when circuit opens
                startBackgroundRecovery();
            }
        }
    }

    /**
     * Reset circuit breaker after successful operation.
     */
    private void resetCircuitBreaker() {
        consecutiveFailures = 0;
        circuitState = CircuitState.CLOSED;

        // Stop background recovery thread when circuit closes
        stopBackgroundRecovery();
    }

    /**
     * Classify failure as permanent or transient using simple error message analysis.
     */
    private boolean isPermanentFailure(Exception e) {
        String message = e.getMessage();
        if (message == null) {
            // No message - default to transient (conservative)
            logger.warn("KMS exception with no message: {}", e.getClass().getSimpleName());
            return false;
        }

        String lowerMessage = message.toLowerCase();

        // Permanent failures - use 5-minute recovery interval
        // These indicate configuration or authorization issues that won't resolve quickly
        if (lowerMessage.contains("is disabled") ||                    // DisabledException
            lowerMessage.contains("disabled") ||                       // Key disabled
            lowerMessage.contains("access denied") ||                  // AccessDeniedException
            lowerMessage.contains("accessdenied") ||                   // AccessDenied variant
            lowerMessage.contains("unauthorized") ||                   // 401/403 errors
            lowerMessage.contains("forbidden") ||                      // 403 errors
            lowerMessage.contains("not found") ||                      // NotFoundException
            lowerMessage.contains("notfound") ||                       // NotFound variant
            lowerMessage.contains("invalid key") ||                    // InvalidKeyId
            lowerMessage.contains("key not found") ||                  // Key doesn't exist
            lowerMessage.contains("does not exist") ||                 // Resource doesn't exist
            lowerMessage.contains("invalid parameter") ||              // Bad configuration
            lowerMessage.contains("malformed") ||                      // Malformed request
            lowerMessage.contains("bad request")) {                    // 400 errors

            logger.warn("Permanent KMS failure detected: {}", message);
            return true;
        }

        // Transient failures - use 30-second recovery interval
        // These indicate temporary issues that may resolve quickly
        if (lowerMessage.contains("throttling") ||                     // ThrottlingException
            lowerMessage.contains("rate limit") ||                     // Rate limiting
            lowerMessage.contains("too many requests") ||              // Rate limiting
            lowerMessage.contains("service unavailable") ||            // 503 errors
            lowerMessage.contains("internal error") ||                 // 500 errors
            lowerMessage.contains("timeout") ||                        // Network timeouts
            lowerMessage.contains("connection") ||                     // Connection issues
            lowerMessage.contains("network")) {                        // Network issues

            logger.warn("Transient KMS failure detected: {}", message);
            return false;
        }

        // Default classification: treat unknown errors as transient (conservative approach)
        // This ensures we don't get stuck in long recovery intervals for unknown issues
        logger.warn("Unknown KMS failure, treating as transient: {}", message);
        return false;
    }

    /**
     * Start background recovery thread for proactive KMS recovery when circuit is open.
     */
    private void startBackgroundRecovery() {
        // Use compareAndSet to ensure only one thread starts the background recovery
        if (backgroundRecoveryStarted.compareAndSet(false, true)) {
            try {
                // Create single-threaded executor for recovery
                backgroundRecoveryExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread thread = new Thread(r, "kms-recovery-" + System.identityHashCode(this));
                    thread.setDaemon(true); // Don't prevent JVM shutdown
                    return thread;
                });

                // Calculate initial delay based on circuit state
                long initialDelay = (circuitState == CircuitState.OPEN_PERMANENT)
                    ? permanentFailureRecoveryIntervalMs
                    : transientFailureRecoveryIntervalMs;

                // Schedule recurring recovery attempts
                backgroundRecoveryExecutor
                    .scheduleWithFixedDelay(
                        this::backgroundRecoveryTask,
                        initialDelay / 2,  // Start sooner for first attempt
                        Math.min(permanentFailureRecoveryIntervalMs, transientFailureRecoveryIntervalMs) / 2, // Check every 15s/2.5min
                        TimeUnit.MILLISECONDS
                    );

                logger.info("Background KMS recovery thread started for circuit state: {}", circuitState);
            } catch (Exception e) {
                logger.error("Failed to start background recovery thread", e);
                backgroundRecoveryStarted.set(false); // Reset on failure
            }
        }
    }

    /**
     * Stop background recovery thread when circuit closes.
     */
    private void stopBackgroundRecovery() {
        if (backgroundRecoveryStarted.compareAndSet(true, false)) {
            if (backgroundRecoveryExecutor != null) {
                backgroundRecoveryExecutor.shutdown();
                try {
                    if (!backgroundRecoveryExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                        backgroundRecoveryExecutor.shutdownNow();
                    }
                    logger.info("Background KMS recovery thread stopped");
                } catch (InterruptedException e) {
                    backgroundRecoveryExecutor.shutdownNow();
                    Thread.currentThread().interrupt();
                }
                backgroundRecoveryExecutor = null;
            }
        }
    }

    /**
     * Background recovery task that runs periodically when circuit is open.
     */
    private void backgroundRecoveryTask() {
        try {
            // Only run when circuit is open
            if (circuitState == CircuitState.CLOSED) {
                stopBackgroundRecovery();
                return;
            }

            // Check if it's time to attempt recovery
            if (!shouldAttemptRecovery()) {
                return;
            }

            logger.debug("Background recovery task attempting KMS recovery. State: {}", circuitState);

            // Attempt recovery using existing logic
            attemptSingleRecovery();

            // If recovery was successful, circuit will be CLOSED and this thread will stop
            if (circuitState == CircuitState.CLOSED) {
                logger.info("Background recovery successful - stopping recovery thread");
                stopBackgroundRecovery();
            }

        } catch (Exception e) {
            logger.warn("Background recovery task failed: {}", e.getMessage());
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
