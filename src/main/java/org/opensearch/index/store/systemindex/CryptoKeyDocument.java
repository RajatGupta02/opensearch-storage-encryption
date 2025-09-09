/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.systemindex;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

/**
 * Document model for storing encrypted data keys in the system index.
 * 
 * This class represents a single document in the crypto keys system index,
 * containing the encrypted data key, KMS key ID, IV, and metadata.
 *
 * @opensearch.internal
 */
public class CryptoKeyDocument implements ToXContentObject {

    private static final String INDEX_UUID_FIELD = "index_uuid";
    private static final String KMS_KEY_ID_FIELD = "kms_key_id";
    private static final String ENCRYPTED_DATA_KEY_FIELD = "encrypted_data_key";
    private static final String IV_FIELD = "iv";
    private static final String CREATED_AT_FIELD = "created_at";
    private static final String ALGORITHM_FIELD = "algorithm";

    private final String indexUuid;
    private final String kmsKeyId;
    private final String encryptedDataKey;  // Base64 encoded
    private final String iv;                // Base64 encoded
    private final Instant createdAt;
    private final String algorithm;

    /**
     * Creates a new CryptoKeyDocument.
     *
     * @param indexUuid the UUID of the index this key belongs to
     * @param kmsKeyId the KMS key ID used to encrypt the data key
     * @param encryptedDataKey the encrypted data key (base64 encoded)
     * @param iv the initialization vector (base64 encoded)
     * @param createdAt when this key was created
     * @param algorithm the encryption algorithm used
     */
    public CryptoKeyDocument(String indexUuid, String kmsKeyId, String encryptedDataKey, String iv, Instant createdAt, String algorithm) {
        this.indexUuid = Objects.requireNonNull(indexUuid, "indexUuid cannot be null");
        this.kmsKeyId = Objects.requireNonNull(kmsKeyId, "kmsKeyId cannot be null");
        this.encryptedDataKey = Objects.requireNonNull(encryptedDataKey, "encryptedDataKey cannot be null");
        this.iv = Objects.requireNonNull(iv, "iv cannot be null");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt cannot be null");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm cannot be null");
    }

    /**
     * Creates a new CryptoKeyDocument with current timestamp.
     *
     * @param indexUuid the UUID of the index this key belongs to
     * @param kmsKeyId the KMS key ID used to encrypt the data key
     * @param encryptedDataKey the encrypted data key (base64 encoded)
     * @param iv the initialization vector (base64 encoded)
     * @param algorithm the encryption algorithm used
     */
    public CryptoKeyDocument(String indexUuid, String kmsKeyId, String encryptedDataKey, String iv, String algorithm) {
        this(indexUuid, kmsKeyId, encryptedDataKey, iv, Instant.now(), algorithm);
    }

    /**
     * Creates a CryptoKeyDocument from a source map (e.g., from search results).
     *
     * @param source the source map
     * @return the CryptoKeyDocument
     */
    @SuppressWarnings("unchecked")
    public static CryptoKeyDocument fromSourceMap(Map<String, Object> source) {
        String indexUuid = (String) source.get(INDEX_UUID_FIELD);
        String kmsKeyId = (String) source.get(KMS_KEY_ID_FIELD);
        String encryptedDataKey = (String) source.get(ENCRYPTED_DATA_KEY_FIELD);
        String iv = (String) source.get(IV_FIELD);
        String algorithm = (String) source.get(ALGORITHM_FIELD);

        Object createdAtObj = source.get(CREATED_AT_FIELD);
        Instant createdAt;
        if (createdAtObj instanceof Long) {
            createdAt = Instant.ofEpochMilli((Long) createdAtObj);
        } else if (createdAtObj instanceof String) {
            createdAt = Instant.parse((String) createdAtObj);
        } else {
            throw new IllegalArgumentException("Invalid created_at format: " + createdAtObj);
        }

        return new CryptoKeyDocument(indexUuid, kmsKeyId, encryptedDataKey, iv, createdAt, algorithm);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(INDEX_UUID_FIELD, indexUuid);
        builder.field(KMS_KEY_ID_FIELD, kmsKeyId);
        builder.field(ENCRYPTED_DATA_KEY_FIELD, encryptedDataKey);
        builder.field(IV_FIELD, iv);
        builder.timeField(CREATED_AT_FIELD, createdAt);
        builder.field(ALGORITHM_FIELD, algorithm);
        builder.endObject();
        return builder;
    }

    /**
     * Gets the document ID to use when storing this document.
     * Uses the index UUID as the document ID for easy retrieval.
     *
     * @return the document ID
     */
    public String getDocumentId() {
        return indexUuid;
    }

    public String getIndexUuid() {
        return indexUuid;
    }

    public String getKmsKeyId() {
        return kmsKeyId;
    }

    public String getEncryptedDataKey() {
        return encryptedDataKey;
    }

    public String getIv() {
        return iv;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        CryptoKeyDocument that = (CryptoKeyDocument) o;
        return Objects.equals(indexUuid, that.indexUuid)
            && Objects.equals(kmsKeyId, that.kmsKeyId)
            && Objects.equals(encryptedDataKey, that.encryptedDataKey)
            && Objects.equals(iv, that.iv)
            && Objects.equals(createdAt, that.createdAt)
            && Objects.equals(algorithm, that.algorithm);
    }

    @Override
    public int hashCode() {
        return Objects.hash(indexUuid, kmsKeyId, encryptedDataKey, iv, createdAt, algorithm);
    }

    @Override
    public String toString() {
        return "CryptoKeyDocument{"
            + "indexUuid='"
            + indexUuid
            + '\''
            + ", kmsKeyId='"
            + kmsKeyId
            + '\''
            + ", algorithm='"
            + algorithm
            + '\''
            + ", createdAt="
            + createdAt
            + '}';
    }
}
