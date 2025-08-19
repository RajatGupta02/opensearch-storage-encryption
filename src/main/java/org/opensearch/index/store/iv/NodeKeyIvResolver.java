/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.iv;

import java.io.IOException;
import java.nio.file.Path;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.store.IOContext;
import org.apache.lucene.store.IndexInput;
import org.apache.lucene.store.IndexOutput;
import org.opensearch.cluster.metadata.CryptoMetadata;
import org.opensearch.common.Randomness;
import org.opensearch.common.crypto.DataKeyPair;
import org.opensearch.common.crypto.MasterKeyProvider;
import org.opensearch.common.settings.Settings;
import org.opensearch.crypto.CryptoHandlerRegistry;
import org.opensearch.index.store.cipher.AesCipherFactory;

/**
 * Node-level implementation of {@link KeyIvResolver} responsible for managing
 * the encryption key and initialization vector (IV) used in encrypting and decrypting
 * Lucene index files at the node level.
 *
 * Metadata files are stored in the node's _state directory:
 * - "keyfile" stores the encrypted data key
 * - "ivFile" stores the base64-encoded IV
 *
 * @opensearch.internal
 */
public class NodeKeyIvResolver implements KeyIvResolver {

    private static final Logger logger = LogManager.getLogger(NodeKeyIvResolver.class);

    private final Directory directory;
    private final MasterKeyProvider keyProvider;
    private final long ttlMillis;

    // Thread-safe TTL-based data key management
    private final AtomicReference<DataKeyHolder> dataKeyRef = new AtomicReference<>();
    private final AtomicBoolean refreshInProgress = new AtomicBoolean(false);

    // Pre-emptive refresh at 80% of TTL to avoid blocking
    private static final double REFRESH_THRESHOLD = 0.8;

    private String iv;

    private static final String IV_FILE = "ivFile";
    private static final String KEY_FILE = "keyfile";

    /**
     * Constructs a new {@link NodeKeyIvResolver} for node-level key management.
     *
     * @param nodeStatePath the node _state directory path
     * @param nodeSettings the node-level settings containing encryption configuration
     * @throws IOException if an I/O error occurs while reading or writing key/IV metadata
     * @throws IllegalArgumentException if required encryption settings are missing
     */
    public NodeKeyIvResolver(Path nodeStatePath, Settings nodeSettings) throws IOException {
        this.directory = FSDirectory.open(nodeStatePath);

        // Extract node-level encryption settings
        String kmsType = nodeSettings.get("cluster.encryption.kms.type");
        if (kmsType == null || kmsType.isEmpty()) {
            throw new IllegalArgumentException("cluster.encryption.kms.type must be set for node-level encryption");
        }

        // Read TTL from settings (default 5 minutes)
        int ttlSeconds = nodeSettings.getAsInt("cluster.encryption.kms.data_key_ttl_seconds", 300);
        this.ttlMillis = ttlSeconds * 1000L;

        // Create key provider using node-level settings
        CryptoMetadata cryptoMetadata = new CryptoMetadata("", kmsType, nodeSettings);
        try {
            this.keyProvider = CryptoHandlerRegistry.getInstance().getCryptoKeyProviderPlugin(kmsType).createKeyProvider(cryptoMetadata);
        } catch (NullPointerException npe) {
            throw new RuntimeException("Could not find key provider: " + kmsType, npe);
        }

        logger.info("Initializing node-level keys with KMS type: {} and TTL: {}s", kmsType, ttlSeconds);
        initialize();
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

            logger.info("Successfully loaded existing node-level encryption keys");
        } catch (java.nio.file.NoSuchFileException e) {
            logger.info("No existing keys found, generating new node-level encryption keys");
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

        logger.info("Successfully generated and stored new node-level encryption keys");
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
     * Returns the data key, using TTL-based refresh with pre-emptive KMS calls.
     * Index operations are never blocked by KMS calls.
     */
    @Override
    public Key getDataKey() {
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

        // Check if pre-emptive refresh needed (at 80% of TTL)
        if (current.needsRefresh(ttlMillis, REFRESH_THRESHOLD)) {
            // Non-blocking: try to start refresh
            if (refreshInProgress.compareAndSet(false, true)) {
                try {
                    byte[] encryptedKey = readByteArrayFile(KEY_FILE);
                    byte[] decryptedKey = keyProvider.decryptKey(encryptedKey);
                    Key newKey = new SecretKeySpec(decryptedKey, "AES");

                    // Atomic update - only after successful KMS call
                    DataKeyHolder newHolder = new DataKeyHolder(newKey, System.currentTimeMillis());
                    dataKeyRef.set(newHolder);

                    logger.debug("Successfully refreshed data key from KMS pre-emptively");

                } catch (Exception e) {
                    // Log error but don't fail - current key continues to work
                    logger.warn("Pre-emptive data key refresh failed, will retry later", e);

                    // Check if current key is truly expired (safety net)
                    if (current.isExpired(ttlMillis)) {
                        // This is critical - expired key and refresh failed
                        logger.error("Data key is expired and refresh failed", e);
                        throw new RuntimeException("Data key expired and KMS refresh failed", e);
                    }
                } finally {
                    refreshInProgress.set(false);
                }
            }
        }

        return current.getDataKey();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getIvBytes() {
        return Base64.getDecoder().decode(iv);
    }
}
