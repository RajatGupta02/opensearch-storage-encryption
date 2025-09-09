/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.systemindex;

import static org.opensearch.cluster.metadata.IndexMetadata.SETTING_INDEX_HIDDEN;
import static org.opensearch.cluster.metadata.IndexMetadata.SETTING_NUMBER_OF_REPLICAS;
import static org.opensearch.cluster.metadata.IndexMetadata.SETTING_NUMBER_OF_SHARDS;

import org.opensearch.common.settings.Settings;
import org.opensearch.indices.SystemIndexDescriptor;

/**
 * System index descriptor for storing encrypted data keys.
 * 
 * This system index stores the mapping between index UUIDs and their encrypted data keys,
 * along with the associated KMS key IDs and initialization vectors.
 *
 * @opensearch.internal
 */
public class CryptoSystemIndexDescriptor {

    /**
     * The name of the system index that stores crypto keys.
     */
    public static final String CRYPTO_KEYS_INDEX_NAME = ".opensearch-crypto-keys";

    /**
     * Version of the system index schema.
     */
    private static final int INDEX_FORMAT_VERSION = 1;

    /**
     * Mapping for the crypto keys system index.
     */
    private static final String CRYPTO_KEYS_MAPPING = """
        {
          "_meta": {
            "version": "%d"
          },
          "properties": {
            "index_uuid": {
              "type": "keyword"
            },
            "kms_key_id": {
              "type": "keyword"
            },
            "encrypted_data_key": {
              "type": "keyword",
              "index": false
            },
            "iv": {
              "type": "keyword",
              "index": false
            },
            "created_at": {
              "type": "date",
              "format": "strict_date_optional_time||epoch_millis"
            },
            "algorithm": {
              "type": "keyword"
            }
          }
        }
        """;

    /**
     * Creates and returns the SystemIndexDescriptor for the crypto keys index.
     *
     * @return the SystemIndexDescriptor for crypto keys storage
     */
    public static SystemIndexDescriptor getDescriptor() {
        return new SystemIndexDescriptor(
            CRYPTO_KEYS_INDEX_NAME + "*",
            "System index for storing encrypted data keys and their KMS mappings"
        );
    }

    /**
     * Gets the settings for the crypto keys system index.
     *
     * @return the index settings
     */
    public static Settings getSystemIndexSettings() {
        return Settings
            .builder()
            .put(SETTING_NUMBER_OF_SHARDS, 1)
            .put(SETTING_NUMBER_OF_REPLICAS, 1)  // For availability
            .put(SETTING_INDEX_HIDDEN, true)
            .put("index.auto_expand_replicas", "0-all") // Auto-expand replicas for availability
            .put("index.refresh_interval", "1s")
            .build();
    }

    /**
     * Gets the mappings for the crypto keys system index.
     *
     * @return the index mappings as a JSON string
     */
    public static String getMappings() {
        return String.format(CRYPTO_KEYS_MAPPING, INDEX_FORMAT_VERSION);
    }

    /**
     * Gets the current format version of the system index.
     *
     * @return the format version
     */
    public static int getFormatVersion() {
        return INDEX_FORMAT_VERSION;
    }
}
