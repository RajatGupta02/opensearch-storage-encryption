/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.kms;

/**
 * Enumeration of KMS failure types used to classify exceptions and determine retry behavior.
 * 
 * @opensearch.internal
 */
public enum KmsFailureType {
    // Retryable failures - temporary issues that may resolve
    NETWORK_TIMEOUT,
    RATE_LIMITED,
    SERVICE_UNAVAILABLE,

    // Non-retryable failures - permanent issues requiring intervention
    KEY_DISABLED,
    KEY_NOT_FOUND,
    ACCESS_DENIED,
    INVALID_KEY_STATE
}
