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
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.routing.IndexRoutingTable;
import org.opensearch.cluster.routing.ShardRouting;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.Randomness;
import org.opensearch.common.crypto.DataKeyPair;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.index.store.cipher.AesCipherFactory;
import org.opensearch.index.store.systemindex.CryptoKeyDocument;
import org.opensearch.index.store.systemindex.CryptoSystemIndexDescriptor;
import org.opensearch.index.store.systemindex.SystemIndexManager;
import org.opensearch.transport.client.Client;

/**
 * System index-based implementation of {@link KeyIvResolver} that stores
 * encrypted data keys in a system index instead of local files.
 * 
 * This resolver provides:
 * - Centralized key storage in .opensearch-crypto-keys system index
 * - In-memory caching for performance (no TTL as requested)  
 * - KMS integration for key encryption/decryption
 * - Thread-safe operations
 *
 * @opensearch.internal
 */
public class SystemIndexKeyIvResolver implements KeyIvResolver {

    private static final Logger logger = LogManager.getLogger(SystemIndexKeyIvResolver.class);

    private final Client client;
    private final String indexUuid;
    private final String kmsKeyId;
    private final MasterKeyProvider keyProvider;
    private final SystemIndexManager systemIndexManager;
    private final ClusterService clusterService;

    // In-memory cache - no TTL refresh as requested
    private final ConcurrentHashMap<String, Key> keyCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, byte[]> ivCache = new ConcurrentHashMap<>();

    // Timeout for waiting for system index readiness (30 seconds)
    private static final long SYSTEM_INDEX_READY_TIMEOUT_MS = 30000L;

    private static final String ALGORITHM = "AES";

    // KMS key ID validation pattern (supports common AWS KMS formats)
    private static final Pattern KMS_KEY_ID_PATTERN = Pattern
        .compile(
            "^(arn:aws:kms:[a-z0-9-]+:\\d{12}:key/)?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$|"
                + "^alias/[a-zA-Z0-9/_-]+$"
        );

    /**
     * Creates a new SystemIndexKeyIvResolver.
     *
     * @param client the OpenSearch client for system index operations
     * @param indexUuid the UUID of the index this resolver manages keys for
     * @param kmsKeyId the KMS key ID to use for encrypting data keys
     * @param provider the JCE provider (not used in this implementation but kept for interface compatibility)
     * @param keyProvider the master key provider for KMS operations
     * @param settings additional settings (unused but kept for compatibility)
     * @param systemIndexManager the system index manager for handling system index lifecycle
     * @param clusterService the cluster service for primary shard detection
     * @throws IllegalArgumentException if any required parameter is null or invalid
     */
    public SystemIndexKeyIvResolver(
        Client client,
        String indexUuid,
        String kmsKeyId,
        Provider provider,
        MasterKeyProvider keyProvider,
        Settings settings,
        SystemIndexManager systemIndexManager,
        ClusterService clusterService
    ) {
        // Validate required parameters
        if (client == null) {
            throw new IllegalArgumentException("Client cannot be null");
        }
        if (indexUuid == null || indexUuid.trim().isEmpty()) {
            throw new IllegalArgumentException("Index UUID cannot be null or empty");
        }
        if (kmsKeyId == null || kmsKeyId.trim().isEmpty()) {
            throw new IllegalArgumentException("KMS key ID cannot be null or empty");
        }
        if (keyProvider == null) {
            throw new IllegalArgumentException("Master key provider cannot be null");
        }
        if (systemIndexManager == null) {
            throw new IllegalArgumentException("System index manager cannot be null");
        }
        if (clusterService == null) {
            throw new IllegalArgumentException("Cluster service cannot be null");
        }

        // Validate KMS key ID format (basic validation)
        if (!isValidKmsKeyId(kmsKeyId)) {
            throw new IllegalArgumentException("Invalid KMS key ID format: " + kmsKeyId);
        }

        this.client = client;
        this.indexUuid = indexUuid.trim();
        this.kmsKeyId = kmsKeyId.trim();
        this.keyProvider = keyProvider;
        this.systemIndexManager = systemIndexManager;
        this.clusterService = clusterService;

        logger.info("SystemIndexKeyIvResolver initialized for index: {} with KMS key: {}", indexUuid, kmsKeyId);
    }

    /**
     * {@inheritDoc}
     * Returns the data key using default behavior (INDEX component type).
     */
    @Override
    public Key getDataKey() {
        return getDataKey(ComponentType.INDEX);
    }

    /**
     * {@inheritDoc}
     * Returns the cached data key or fetches it from the system index.
     * Component type is ignored in this implementation since we don't have TTL refresh logic.
     */
    @Override
    public Key getDataKey(ComponentType componentType) {
        // Check cache first
        Key cachedKey = keyCache.get(indexUuid);
        if (cachedKey != null) {
            logger.debug("Returning cached data key for index: {}", indexUuid);
            return cachedKey;
        }

        // Fetch from system index synchronously
        try {
            return fetchOrCreateDataKey();
        } catch (Exception e) {
            logger.error("Failed to fetch or create data key for index: {}", indexUuid, e);
            throw new RuntimeException("Failed to retrieve data key from system index", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getIvBytes() {
        // Check cache first
        byte[] cachedIv = ivCache.get(indexUuid);
        if (cachedIv != null) {
            logger.debug("Returning cached IV for index: {}", indexUuid);
            return cachedIv;
        }

        // Fetch from system index synchronously
        try {
            fetchOrCreateDataKey(); // This will populate both key and IV caches
            return ivCache.get(indexUuid);
        } catch (Exception e) {
            logger.error("Failed to fetch or create IV for index: {}", indexUuid, e);
            throw new RuntimeException("Failed to retrieve IV from system index", e);
        }
    }

    /**
     * Fetches the crypto key document from system index or creates a new one if not found.
     * Uses single-writer pattern: only the primary node creates keys, others wait and read.
     * 
     * @return the decrypted data key
     * @throws IOException if system index operations fail
     */
    private Key fetchOrCreateDataKey() throws IOException {
        logger.debug("Fetching crypto key document for index: {}", indexUuid);

        // Ensure system index exists before any operations
        ensureSystemIndexExists();

        GetRequest getRequest = new GetRequest(CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME).id(indexUuid);
        GetResponse getResponse = client.get(getRequest).actionGet();

        if (getResponse.isExists()) {
            // Document exists - parse it (ALL nodes do this)
            return parseAndCacheExistingKey(getResponse);
        } else {
            // Document doesn't exist
            if (isPrimaryNodeForSystemIndex()) {
                // I'm primary - create the key
                logger.info("Primary node creating crypto key for index: {}", indexUuid);
                return createAndStoreNewKey();
            } else {
                // I'm not primary - wait for primary to create it, then read
                logger.info("Non-primary node waiting for crypto key creation: {}", indexUuid);
                return waitForKeyCreationAndRead();
            }
        }
    }

    /**
     * Parses and caches an existing crypto key document.
     * 
     * @param getResponse the response containing the existing document
     * @return the decrypted data key
     * @throws IOException if parsing fails
     */
    private Key parseAndCacheExistingKey(GetResponse getResponse) throws IOException {
        logger.debug("Found existing crypto key document for index: {}", indexUuid);

        CryptoKeyDocument document = CryptoKeyDocument.fromSourceMap(getResponse.getSourceAsMap());

        // Decrypt the data key using KMS
        byte[] encryptedKeyBytes = Base64.getDecoder().decode(document.getEncryptedDataKey());
        byte[] decryptedKeyBytes = keyProvider.decryptKey(encryptedKeyBytes);
        Key dataKey = new SecretKeySpec(decryptedKeyBytes, ALGORITHM);

        // Decode IV
        byte[] ivBytes = Base64.getDecoder().decode(document.getIv());

        // Cache both key and IV
        keyCache.put(indexUuid, dataKey);
        ivCache.put(indexUuid, ivBytes);

        // Log key/IV loading for debugging
        logger
            .info(
                "Successfully loaded and cached crypto key for index: {} - Key hash: {}, IV hash: {}",
                indexUuid,
                java.util.Arrays.hashCode(decryptedKeyBytes),
                java.util.Arrays.hashCode(ivBytes)
            );
        return dataKey;
    }

    /**
     * Determines if the current node holds the primary shard for the crypto system index.
     * 
     * @return true if this node is the primary, false otherwise
     */
    private boolean isPrimaryNodeForSystemIndex() {
        try {
            IndexRoutingTable routingTable = clusterService
                .state()
                .routingTable()
                .index(CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME);

            if (routingTable == null) {
                logger.debug("System index routing not found, assuming non-primary");
                return false; // Safe default: don't write if uncertain
            }

            ShardRouting primaryShard = routingTable.shard(0).primaryShard();
            String localNodeId = clusterService.localNode().getId();

            boolean isPrimary = primaryShard.currentNodeId().equals(localNodeId);
            logger
                .debug(
                    "Primary check for system index: isPrimary={}, localNode={}, primaryNode={}",
                    isPrimary,
                    localNodeId,
                    primaryShard.currentNodeId()
                );

            return isPrimary;
        } catch (Exception e) {
            logger.warn("Failed to determine primary node status, assuming non-primary", e);
            return false; // Safe default: don't write if uncertain
        }
    }

    /**
     * Waits for the primary node to create the crypto key, then reads it.
     * Simple retry logic with exponential backoff.
     * 
     * @return the decrypted data key created by the primary node
     * @throws IOException if timeout or other failure occurs
     */
    private Key waitForKeyCreationAndRead() throws IOException {
        int maxRetries = 10;
        int delayMs = 200; // Start with 200ms

        GetRequest getRequest = new GetRequest(CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME).id(indexUuid);

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                Thread.sleep(delayMs);

                GetResponse retryResponse = client.get(getRequest).actionGet();
                if (retryResponse.isExists()) {
                    logger.info("Found crypto key created by primary node after {} attempts", attempt);
                    return parseAndCacheExistingKey(retryResponse);
                }

                // Exponential backoff with jitter
                delayMs = Math.min(delayMs * 2, 5000); // Max 5 seconds

                logger.debug("Crypto key not yet created by primary, attempt {}/{}, retrying in {}ms", attempt, maxRetries, delayMs);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while waiting for crypto key creation", e);
            }
        }

        throw new IOException("Timeout waiting for crypto key creation by primary node after " + maxRetries + " attempts");
    }

    /**
     * Creates a new data key, encrypts it with KMS, and stores it in the system index.
     * Simplified version for single-writer pattern - only the primary node calls this method.
     *
     * @return the new decrypted data key
     * @throws IOException if key creation or storage fails
     */
    private Key createAndStoreNewKey() throws IOException {
        try {
            // Generate new data key pair using KMS
            DataKeyPair dataKeyPair = keyProvider.generateDataPair();
            byte[] encryptedKeyBytes = dataKeyPair.getEncryptedKey();
            byte[] decryptedKeyBytes = keyProvider.decryptKey(encryptedKeyBytes);

            // Generate new IV
            byte[] ivBytes = new byte[AesCipherFactory.IV_ARRAY_LENGTH];
            SecureRandom random = Randomness.createSecure();
            random.nextBytes(ivBytes);

            // Log key/IV creation for debugging
            logger
                .info(
                    "Primary node creating new crypto key for index: {} - Key hash: {}, IV hash: {}",
                    indexUuid,
                    java.util.Arrays.hashCode(decryptedKeyBytes),
                    java.util.Arrays.hashCode(ivBytes)
                );

            // Create document
            CryptoKeyDocument document = new CryptoKeyDocument(
                indexUuid,
                kmsKeyId,
                Base64.getEncoder().encodeToString(encryptedKeyBytes),
                Base64.getEncoder().encodeToString(ivBytes),
                ALGORITHM
            );

            // Store in system index - no race conditions since only primary writes
            IndexRequest indexRequest = new IndexRequest(CryptoSystemIndexDescriptor.CRYPTO_KEYS_INDEX_NAME)
                .id(document.getDocumentId())
                .source(
                    document.toXContent(org.opensearch.common.xcontent.XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS).toString(),
                    XContentType.JSON
                )
                .setRefreshPolicy("wait_for");

            IndexResponse indexResponse = client.index(indexRequest).actionGet();

            if (indexResponse.getResult() == DocWriteResponse.Result.CREATED
                || indexResponse.getResult() == DocWriteResponse.Result.UPDATED) {

                // Success - cache and return our key
                Key dataKey = new SecretKeySpec(decryptedKeyBytes, ALGORITHM);
                keyCache.put(indexUuid, dataKey);
                ivCache.put(indexUuid, ivBytes);

                logger.info("Successfully created and stored new crypto key for index: {} in system index", indexUuid);
                return dataKey;
            } else {
                throw new IOException("Unexpected index response: " + indexResponse.getResult());
            }

        } catch (Exception e) {
            logger.error("Failed to create and store new crypto key for index: {}", indexUuid, e);
            throw new IOException("Failed to create new crypto key", e);
        }
    }

    /**
     * Clears the cache for this resolver (useful for testing).
     */
    public void clearCache() {
        keyCache.remove(indexUuid);
        ivCache.remove(indexUuid);
        logger.debug("Cleared cache for index: {}", indexUuid);
    }

    /**
     * Gets the index UUID this resolver manages.
     *
     * @return the index UUID
     */
    public String getIndexUuid() {
        return indexUuid;
    }

    /**
     * Gets the KMS key ID used by this resolver.
     *
     * @return the KMS key ID
     */
    public String getKmsKeyId() {
        return kmsKeyId;
    }

    /**
     * Validates KMS key ID format.
     * Supports AWS KMS key formats including:
     * - UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
     * - Full ARN: arn:aws:kms:region:account:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
     * - Alias format: alias/my-alias-name
     *
     * @param kmsKeyId the KMS key ID to validate
     * @return true if the format is valid, false otherwise
     */
    private static boolean isValidKmsKeyId(String kmsKeyId) {
        if (kmsKeyId == null || kmsKeyId.trim().isEmpty()) {
            return false;
        }
        return KMS_KEY_ID_PATTERN.matcher(kmsKeyId.trim()).matches();
    }

    /**
     * Ensures the crypto system index is ready for operations.
     * Uses SystemIndexManager to check readiness and handle retries if needed.
     *
     * @throws IOException if system index is not ready and cannot be made ready
     */
    private void ensureSystemIndexExists() throws IOException {
        // Check if system index is already ready
        if (systemIndexManager.isSystemIndexReady()) {
            logger.debug("System index is ready for operations");
            return;
        }

        logger.info("System index not ready, waiting for readiness...");

        // Wait for system index to become ready with timeout
        if (systemIndexManager.waitForSystemIndexReady(SYSTEM_INDEX_READY_TIMEOUT_MS)) {
            logger.info("System index became ready for operations");
            return;
        }

        // If still not ready, try to retry creation
        logger.warn("System index not ready within timeout, attempting retry...");
        if (systemIndexManager.retrySystemIndexCreation()) {
            logger.info("System index creation retry succeeded");
            return;
        }

        // Final failure
        String errorMsg = "System index is not ready and retry failed - cannot perform encryption operations";
        logger.error(errorMsg);
        throw new IOException(errorMsg);
    }
}
