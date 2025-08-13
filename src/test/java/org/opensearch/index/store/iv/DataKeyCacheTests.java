/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.iv;

import static org.junit.Assert.*;

import java.security.Key;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.spec.SecretKeySpec;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for DataKeyCache TTL-based caching functionality.
 */
public class DataKeyCacheTests {

    private DataKeyCache cache;
    private static final String TEST_KEY_ID = "test-key-123";
    private static final long SHORT_TTL_MS = 100; // 100ms for fast testing

    @Before
    public void setUp() {
        cache = new DataKeyCache(SHORT_TTL_MS, 10);
    }

    @After
    public void tearDown() {
        if (cache != null) {
            cache.shutdown();
        }
    }

    @Test
    public void testCacheHitAndMiss() {
        AtomicInteger keyGenerationCount = new AtomicInteger(0);

        // First call should be a cache miss
        Key key1 = cache.getDataKey(TEST_KEY_ID, () -> {
            keyGenerationCount.incrementAndGet();
            return new SecretKeySpec(new byte[32], "AES");
        });
        assertNotNull(key1);
        assertEquals(1, keyGenerationCount.get());

        // Second call should be a cache hit
        Key key2 = cache.getDataKey(TEST_KEY_ID, () -> {
            keyGenerationCount.incrementAndGet();
            return new SecretKeySpec(new byte[32], "AES");
        });
        assertNotNull(key2);
        assertEquals(1, keyGenerationCount.get()); // Should not increment
        assertSame(key1, key2); // Should be the same instance
    }

    @Test
    public void testCacheExpiration() throws InterruptedException {
        AtomicInteger keyGenerationCount = new AtomicInteger(0);

        // First call - cache miss
        Key key1 = cache.getDataKey(TEST_KEY_ID, () -> {
            keyGenerationCount.incrementAndGet();
            return new SecretKeySpec(new byte[32], "AES");
        });
        assertNotNull(key1);
        assertEquals(1, keyGenerationCount.get());

        // Wait for cache to expire
        Thread.sleep(SHORT_TTL_MS + 50);

        // Should be cache miss again due to expiration
        Key key2 = cache.getDataKey(TEST_KEY_ID, () -> {
            keyGenerationCount.incrementAndGet();
            return new SecretKeySpec(new byte[32], "AES");
        });
        assertNotNull(key2);
        assertEquals(2, keyGenerationCount.get()); // Should increment
    }

    @Test
    public void testConcurrentAccess() throws InterruptedException {
        final int threadCount = 10;
        final CountDownLatch startLatch = new CountDownLatch(1);
        final CountDownLatch finishLatch = new CountDownLatch(threadCount);
        final AtomicInteger keyGenerationCount = new AtomicInteger(0);
        final Key[] results = new Key[threadCount];

        // Create multiple threads accessing cache simultaneously
        for (int i = 0; i < threadCount; i++) {
            final int threadIndex = i;
            new Thread(() -> {
                try {
                    startLatch.await();
                    results[threadIndex] = cache.getDataKey(TEST_KEY_ID, () -> {
                        keyGenerationCount.incrementAndGet();
                        return new SecretKeySpec(new byte[32], "AES");
                    });
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    finishLatch.countDown();
                }
            }).start();
        }

        // Start all threads simultaneously
        startLatch.countDown();
        finishLatch.await(5, TimeUnit.SECONDS);

        // All threads should get the same key instance (only one should be generated)
        assertEquals(1, keyGenerationCount.get());
        Key firstKey = results[0];
        assertNotNull(firstKey);
        for (Key result : results) {
            assertNotNull(result);
            assertSame(firstKey, result);
        }
    }

    @Test
    public void testCacheInvalidation() {
        AtomicInteger keyGenerationCount = new AtomicInteger(0);

        // First call - cache miss
        Key key1 = cache.getDataKey(TEST_KEY_ID, () -> {
            keyGenerationCount.incrementAndGet();
            return new SecretKeySpec(new byte[32], "AES");
        });
        assertNotNull(key1);
        assertEquals(1, keyGenerationCount.get());

        // Manually invalidate the key
        cache.invalidateKey(TEST_KEY_ID);

        // Next call should be cache miss due to invalidation
        Key key2 = cache.getDataKey(TEST_KEY_ID, () -> {
            keyGenerationCount.incrementAndGet();
            return new SecretKeySpec(new byte[32], "AES");
        });
        assertNotNull(key2);
        assertEquals(2, keyGenerationCount.get()); // Should increment
    }

    @Test
    public void testCacheStats() {
        // Add some entries
        cache.getDataKey("key1", () -> new SecretKeySpec(new byte[32], "AES"));
        cache.getDataKey("key2", () -> new SecretKeySpec(new byte[32], "AES"));

        DataKeyCache.CacheStats stats = cache.getStats();
        assertNotNull(stats);
        assertEquals(2, stats.totalEntries);
        assertEquals(SHORT_TTL_MS, stats.ttlMillis);
        assertEquals(10, stats.maxSize);
    }

    @Test
    public void testErrorFallback() {
        AtomicInteger attemptCount = new AtomicInteger(0);

        // First call succeeds
        Key key1 = cache.getDataKey(TEST_KEY_ID, () -> {
            attemptCount.incrementAndGet();
            return new SecretKeySpec(new byte[32], "AES");
        });
        assertNotNull(key1);
        assertEquals(1, attemptCount.get());

        // Wait for expiration
        try {
            Thread.sleep(SHORT_TTL_MS + 50);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Second call fails, should return expired key as fallback
        Key key2 = cache.getDataKey(TEST_KEY_ID, () -> {
            attemptCount.incrementAndGet();
            throw new RuntimeException("KMS failure simulation");
        });
        assertNotNull(key2);
        assertEquals(2, attemptCount.get());
        assertSame(key1, key2); // Should return the expired key as fallback
    }

    @Test
    public void testCacheClear() {
        // Add entries
        cache.getDataKey("key1", () -> new SecretKeySpec(new byte[32], "AES"));
        cache.getDataKey("key2", () -> new SecretKeySpec(new byte[32], "AES"));

        DataKeyCache.CacheStats statsBefore = cache.getStats();
        assertEquals(2, statsBefore.totalEntries);

        // Clear cache
        cache.clear();

        DataKeyCache.CacheStats statsAfter = cache.getStats();
        assertEquals(0, statsAfter.totalEntries);
    }
}
