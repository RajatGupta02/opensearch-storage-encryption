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

    private final Directory directory;
    private final MasterKeyProvider keyProvider;
    private final DataKeyCache dataKeyCache;

    private String iv;

    private static final String IV_FILE = "ivFile";
    private static final String KEY_FILE = "keyfile";

    /**
     * Constructs a new {@link DefaultKeyIvResolver} and ensures the key and IV are initialized.
     *
     * @param directory the Lucene directory to read/write metadata files
     * @param provider the JCE provider used for cipher operations
     * @param keyProvider the master key provider used to encrypt/decrypt data keys
     * @param settings the settings containing cache configuration
     * @throws IOException if an I/O error occurs while reading or writing key/IV metadata
     */
    public DefaultKeyIvResolver(Directory directory, Provider provider, MasterKeyProvider keyProvider, Settings settings)
        throws IOException {
        this.directory = directory;
        this.keyProvider = keyProvider;

        // Initialize cache with settings
        int ttlSeconds = settings.getAsInt("index.store.kms.data_key_cache_ttl_seconds", 300);
        int maxSize = settings.getAsInt("index.store.kms.data_key_cache_max_size", 100);
        this.dataKeyCache = new DataKeyCache(ttlSeconds * 1000L, maxSize);

        initialize();
    }

    /**
     * Constructs a new {@link DefaultKeyIvResolver} with default cache settings.
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
     * Data key is now loaded on-demand through the cache.
     */
    private void initialize() throws IOException {
        try {
            iv = readStringFile(IV_FILE);
            // Pre-load the key into cache on initialization
            getDataKey();
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

        // Pre-load the key into cache after creating new key and IV
        getDataKey();
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
     * Returns the data key, using TTL-based caching with automatic refresh from KMS.
     */
    @Override
    public Key getDataKey() {
        // Use cache with keyProvider's keyId as cache key, fallback to "default" if not available
        String keyId;
        try {
            keyId = keyProvider.getKeyId();
        } catch (Exception e) {
            keyId = "default";
        }

        return dataKeyCache.getDataKey(keyId, () -> {
            try {
                // Read encrypted key from file and decrypt via KMS
                byte[] encryptedKey = readByteArrayFile(KEY_FILE);
                byte[] decryptedKey = keyProvider.decryptKey(encryptedKey);
                return new SecretKeySpec(decryptedKey, "AES");
            } catch (IOException e) {
                throw new RuntimeException("Failed to refresh data key from KMS", e);
            }
        });
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getIvBytes() {
        return Base64.getDecoder().decode(iv);
    }

    /**
     * Shuts down the data key cache and releases resources.
     * Should be called when the resolver is no longer needed.
     */
    public void shutdown() {
        if (dataKeyCache != null) {
            dataKeyCache.shutdown();
        }
    }

    /**
     * Returns cache statistics for monitoring purposes.
     *
     * @return cache statistics
     */
    public DataKeyCache.CacheStats getCacheStats() {
        return dataKeyCache != null ? dataKeyCache.getStats() : null;
    }

    /**
     * Invalidates a specific key from the cache.
     *
     * @param keyId the key identifier to invalidate
     */
    public void invalidateKey(String keyId) {
        if (dataKeyCache != null) {
            dataKeyCache.invalidateKey(keyId);
        }
    }
}
