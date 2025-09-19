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
 * Uses HTTP status code-based classification when available, with fallback to basic
 * exception type checking for network and timeout issues.
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
        // First check for network and timeout exceptions (retryable)
        if (exception instanceof ConnectException || exception instanceof SocketTimeoutException || exception instanceof TimeoutException) {
            return KmsFailureType.NETWORK_TIMEOUT;
        }

        // Try to extract HTTP status code from exception
        int statusCode = extractHttpStatusCode(exception);
        if (statusCode > 0) {
            return classifyByStatusCode(statusCode);
        }

        // Default to network timeout for unknown exceptions (retryable)
        return KmsFailureType.NETWORK_TIMEOUT;
    }

    /**
     * Extracts HTTP status code from exception if available.
     * 
     * @param exception the exception to extract status code from
     * @return the HTTP status code, or -1 if not found
     */
    private static int extractHttpStatusCode(Exception exception) {
        String message = exception.getMessage();
        if (message == null) {
            return -1;
        }

        // Look for common HTTP status code patterns in exception messages
        // AWS SDK typically includes status codes in format "Status Code: 403" or "(Status Code: 404)"
        if (message.contains("Status Code:") || message.contains("status code:")) {
            try {
                String[] parts = message.split("(?i)status code:?\\s*");
                if (parts.length > 1) {
                    String statusPart = parts[1].trim();
                    // Extract first number from the status part
                    StringBuilder sb = new StringBuilder();
                    for (char c : statusPart.toCharArray()) {
                        if (Character.isDigit(c)) {
                            sb.append(c);
                        } else if (sb.length() > 0) {
                            break; // Stop at first non-digit after finding digits
                        }
                    }
                    if (sb.length() > 0) {
                        return Integer.parseInt(sb.toString());
                    }
                }
            } catch (NumberFormatException e) {
                // Ignore parsing errors, fall through to default
            }
        }

        return -1;
    }

    /**
     * Classifies failure based on HTTP status code.
     * 
     * @param statusCode the HTTP status code
     * @return the failure type
     */
    private static KmsFailureType classifyByStatusCode(int statusCode) {
        if (statusCode == 429) {
            return KmsFailureType.RATE_LIMITED;
        } else if (statusCode >= 500 && statusCode < 600) {
            return KmsFailureType.SERVICE_UNAVAILABLE;
        } else if (statusCode == 403) {
            return KmsFailureType.ACCESS_DENIED;
        } else if (statusCode == 404) {
            return KmsFailureType.KEY_NOT_FOUND;
        } else if (statusCode >= 400 && statusCode < 500) {
            return KmsFailureType.KEY_DISABLED;
        }

        // Unknown status codes default to retryable
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
