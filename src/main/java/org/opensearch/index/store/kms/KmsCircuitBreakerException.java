/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.kms;

/**
 * Lightweight exception thrown when the KMS circuit breaker is active.
 * This exception does not generate a stack trace to avoid log spam when
 * multiple operations are blocked due to KMS failures.
 *
 * @opensearch.internal
 */
public class KmsCircuitBreakerException extends RuntimeException {

    private final KmsFailureType failureType;

    /**
     * Constructs a new KMS circuit breaker exception with the specified failure type.
     *
     * @param failureType the type of KMS failure that triggered the circuit breaker
     */
    public KmsCircuitBreakerException(KmsFailureType failureType) {
        super(createMessage(failureType));
        this.failureType = failureType;
    }

    /**
     * Constructs a new KMS circuit breaker exception with the specified failure type and cause.
     *
     * @param failureType the type of KMS failure that triggered the circuit breaker
     * @param cause the underlying cause of the failure
     */
    public KmsCircuitBreakerException(KmsFailureType failureType, Throwable cause) {
        super(createMessage(failureType), cause);
        this.failureType = failureType;
    }

    /**
     * Returns the failure type that triggered the circuit breaker.
     *
     * @return the failure type
     */
    public KmsFailureType getFailureType() {
        return failureType;
    }

    /**
     * Override to prevent stack trace generation, making this exception lightweight
     * and eliminating log spam when thrown repeatedly.
     *
     * @return this exception instance without filling in the stack trace
     */
    @Override
    public synchronized Throwable fillInStackTrace() {
        // Don't fill in stack trace - makes this exception very lightweight
        return this;
    }

    /**
     * Creates an actionable error message based on the failure type.
     */
    private static String createMessage(KmsFailureType failureType) {
        switch (failureType) {
            case ACCESS_DENIED:
                return "KMS access blocked by circuit breaker due to ACCESS_DENIED failure. "
                    + "Check KMS key permissions and ensure the key is enabled and accessible.";
            case KEY_NOT_FOUND:
                return "KMS access blocked by circuit breaker due to KEY_NOT_FOUND failure. "
                    + "Verify the KMS key exists and is accessible from this region.";
            case KEY_DISABLED:
                return "KMS access blocked by circuit breaker due to KEY_DISABLED failure. "
                    + "The KMS key has been disabled. Enable the key to restore functionality.";
            case INVALID_KEY_STATE:
                return "KMS access blocked by circuit breaker due to INVALID_KEY_STATE failure. "
                    + "The KMS key is in an invalid state. Check key status and configuration.";
            case SERVICE_UNAVAILABLE:
                return "KMS access blocked by circuit breaker due to SERVICE_UNAVAILABLE failure. "
                    + "KMS service may be experiencing issues. Monitor service status and retry when available.";
            case RATE_LIMITED:
                return "KMS access blocked by circuit breaker due to RATE_LIMITED failure. "
                    + "KMS request rate limits exceeded. Reduce request frequency or request limit increases.";
            case NETWORK_TIMEOUT:
                return "KMS access blocked by circuit breaker due to NETWORK_TIMEOUT failure. "
                    + "Network connectivity issues detected. Check network connectivity to KMS service.";
            default:
                return "KMS access blocked by circuit breaker due to "
                    + failureType
                    + " failure. "
                    + "Check KMS configuration and service availability.";
        }
    }
}
