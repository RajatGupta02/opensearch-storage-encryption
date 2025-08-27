/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.kms;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.concurrent.TimeoutException;

/**
 * Utility class for classifying KMS failures into retryable and non-retryable categories.
 * This classification determines whether operations should continue with existing keys
 * or fail immediately with circuit breaker activation.
 * 
 * Uses pattern matching on exception types and messages since specific KMS SDK
 * exceptions may not be available depending on the MasterKeyProvider implementation.
 * 
 * @opensearch.internal
 */
public class KmsFailureClassifier {

    /**
     * Classifies a KMS exception into a specific failure type.
     * 
     * @param exception the exception to classify
     * @return the failure type
     */
    public static KmsFailureType classify(Exception exception) {
        String exceptionMessage = exception.getMessage() != null ? exception.getMessage().toLowerCase() : "";
        String exceptionType = exception.getClass().getSimpleName().toLowerCase();

        // Network and timeout related exceptions (retryable)
        if (exception instanceof ConnectException
            || exception instanceof SocketTimeoutException
            || exception instanceof TimeoutException
            || exceptionMessage.contains("timeout")
            || exceptionMessage.contains("connection")
            || exceptionMessage.contains("network")) {
            return KmsFailureType.NETWORK_TIMEOUT;
        }

        // Rate limiting (retryable)
        if (exceptionMessage.contains("throttl")
            || exceptionMessage.contains("rate limit")
            || exceptionMessage.contains("too many requests")
            || exceptionType.contains("throttl")) {
            return KmsFailureType.RATE_LIMITED;
        }

        // Service unavailable (retryable)
        if (exceptionMessage.contains("service unavailable")
            || exceptionMessage.contains("internal error")
            || exceptionMessage.contains("temporarily unavailable")
            || exceptionType.contains("internal")
            || exceptionType.contains("unavailable")) {
            return KmsFailureType.SERVICE_UNAVAILABLE;
        }

        // Key disabled (non-retryable)
        if (exceptionMessage.contains("disabled") || exceptionMessage.contains("key is disabled") || exceptionType.contains("disabled")) {
            return KmsFailureType.KEY_DISABLED;
        }

        // Key not found (non-retryable)
        if (exceptionMessage.contains("not found")
            || exceptionMessage.contains("does not exist")
            || exceptionMessage.contains("invalid key")
            || exceptionType.contains("notfound")
            || exceptionType.contains("notexist")) {
            return KmsFailureType.KEY_NOT_FOUND;
        }

        // Access denied (non-retryable)
        if (exceptionMessage.contains("access denied")
            || exceptionMessage.contains("unauthorized")
            || exceptionMessage.contains("permission")
            || exceptionMessage.contains("forbidden")
            || exceptionType.contains("access")
            || exceptionType.contains("unauthorized")
            || exceptionType.contains("forbidden")) {
            return KmsFailureType.ACCESS_DENIED;
        }

        // Invalid key state (non-retryable)
        if (exceptionMessage.contains("invalid state") || exceptionMessage.contains("key state") || exceptionMessage.contains("unusable")) {
            return KmsFailureType.INVALID_KEY_STATE;
        }

        // Default to network timeout for unknown exceptions (retryable)
        // This is a conservative approach - we prefer false positives for retryable failures
        return KmsFailureType.NETWORK_TIMEOUT;
    }

    /**
     * Determines if a failure type is retryable.
     * Retryable failures should continue with existing keys and retry on TTL.
     * Non-retryable failures should activate circuit breaker.
     * 
     * @param failureType the failure type to check
     * @return true if the failure is retryable
     */
    public static boolean isRetryable(KmsFailureType failureType) {
        switch (failureType) {
            case NETWORK_TIMEOUT:
            case RATE_LIMITED:
            case SERVICE_UNAVAILABLE:
                return true;

            case KEY_DISABLED:
            case KEY_NOT_FOUND:
            case ACCESS_DENIED:
            case INVALID_KEY_STATE:
                return false;

            default:
                // Unknown failure types default to retryable for safety
                return true;
        }
    }
}
