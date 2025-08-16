/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.iv;

import javax.crypto.spec.SecretKeySpec;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Unit tests for DataKeyHolder TTL-based functionality.
 */
public class DataKeyHolderTests extends OpenSearchTestCase {

    private static final long TTL_MS = 1000; // 1 second for testing
    private static final double REFRESH_THRESHOLD = 0.8; // 80%

    public void testDataKeyHolderCreation() {
        SecretKeySpec testKey = new SecretKeySpec(new byte[32], "AES");
        long refreshTime = System.currentTimeMillis();

        DataKeyHolder holder = new DataKeyHolder(testKey, refreshTime);

        assertSame(testKey, holder.getDataKey());
        assertEquals(refreshTime, holder.getRefreshTime());
        assertTrue(holder.getAge() >= 0);
    }

    public void testNullKeyValidation() {
        expectThrows(IllegalArgumentException.class, () -> { new DataKeyHolder(null, System.currentTimeMillis()); });
    }

    public void testRefreshThresholdValidation() {
        SecretKeySpec testKey = new SecretKeySpec(new byte[32], "AES");
        DataKeyHolder holder = new DataKeyHolder(testKey, System.currentTimeMillis());

        // Valid threshold
        assertFalse(holder.needsRefresh(TTL_MS, 0.8));

        // Invalid thresholds
        expectThrows(IllegalArgumentException.class, () -> { holder.needsRefresh(TTL_MS, -0.1); });

        expectThrows(IllegalArgumentException.class, () -> { holder.needsRefresh(TTL_MS, 1.1); });
    }

    public void testNeedsRefreshLogic() throws InterruptedException {
        SecretKeySpec testKey = new SecretKeySpec(new byte[32], "AES");
        DataKeyHolder holder = new DataKeyHolder(testKey, System.currentTimeMillis());

        // Initially should not need refresh
        assertFalse(holder.needsRefresh(TTL_MS, REFRESH_THRESHOLD));

        // Wait for refresh threshold to be reached (80% of 1000ms = 800ms)
        Thread.sleep(850);

        // Now should need refresh
        assertTrue(holder.needsRefresh(TTL_MS, REFRESH_THRESHOLD));
    }

    public void testExpirationLogic() throws InterruptedException {
        SecretKeySpec testKey = new SecretKeySpec(new byte[32], "AES");
        DataKeyHolder holder = new DataKeyHolder(testKey, System.currentTimeMillis());

        // Initially should not be expired
        assertFalse(holder.isExpired(TTL_MS));

        // Wait for expiration
        Thread.sleep(TTL_MS + 100);

        // Now should be expired
        assertTrue(holder.isExpired(TTL_MS));
    }

    public void testAgeCalculation() throws InterruptedException {
        SecretKeySpec testKey = new SecretKeySpec(new byte[32], "AES");
        DataKeyHolder holder = new DataKeyHolder(testKey, System.currentTimeMillis());

        long initialAge = holder.getAge();
        assertTrue(initialAge >= 0 && initialAge < 100); // Should be very small initially

        Thread.sleep(100);

        long laterAge = holder.getAge();
        assertTrue(laterAge > initialAge);
        assertTrue(laterAge >= 100);
    }

    public void testToString() {
        SecretKeySpec testKey = new SecretKeySpec(new byte[32], "AES");
        long refreshTime = System.currentTimeMillis();
        DataKeyHolder holder = new DataKeyHolder(testKey, refreshTime);

        String str = holder.toString();
        assertNotNull(str);
        assertTrue(str.contains("DataKeyHolder"));
        assertTrue(str.contains("refreshTime=" + refreshTime));
        assertTrue(str.contains("age="));
    }
}
