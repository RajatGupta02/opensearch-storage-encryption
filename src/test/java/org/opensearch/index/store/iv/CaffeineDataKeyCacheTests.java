/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.iv;

import java.security.Key;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.spec.SecretKeySpec;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Unit tests for CaffeineDataKeyCache TTL-based caching functionality.
 */
public class CaffeineDataKeyCacheTests extends OpenSearchTestCase {

    private CaffeineDataKeyCache cache;
    private static final String TEST_KEY_ID = "test-key-123";
    private static final long SHORT_TTL_MS = 100; // 100ms for fast testing

    @Override
    public void setUp() throws Exception {
        super.setUp();
        cache = new CaffeineDataKeyCache(SHORT_TTL_MS, 10);
    }

    @Override
    public void tearDown() throws Exception {
        if (cache != null) {
            cache.shutdown();
        }
        super.tearDown();
    }

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

    public void testCacheStats() {
        // Add some entries
        cache.getDataKey("key1", () -> new SecretKeySpec(new byte[32], "AES"));
        cache.getDataKey("key2", () -> new SecretKeySpec(new byte[32], "AES"));

        CaffeineDataKeyCache.CacheStatistics stats = cache.getStats();
        assertNotNull(stats);
        assertEquals(2, stats.estimatedSize);
        assertEquals(SHORT_TTL_MS, stats.ttlMillis);
        assertEquals(10, stats.maxSize);

        // Verify hit rate calculation
        assertTrue(stats.getHitRate() >= 0.0 && stats.getHitRate() <= 1.0);
    }

    public void testErrorHandling() {
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

        // Second call fails - Caffeine removes expired entries automatically,
        // so no fallback is available, expect exception
        try {
            cache.getDataKey(TEST_KEY_ID, () -> {
                attemptCount.incrementAndGet();
                throw new RuntimeException("KMS failure simulation");
            });
            fail("Expected RuntimeException due to KMS failure with no fallback");
        } catch (RuntimeException e) {
            assertEquals("Failed to retrieve data key and no fallback available", e.getMessage());
            assertEquals(2, attemptCount.get());
        }
    }

    public void testCacheClear() {
        // Add entries
        cache.getDataKey("key1", () -> new SecretKeySpec(new byte[32], "AES"));
        cache.getDataKey("key2", () -> new SecretKeySpec(new byte[32], "AES"));

        CaffeineDataKeyCache.CacheStatistics statsBefore = cache.getStats();
        assertEquals(2, statsBefore.estimatedSize);

        // Clear cache
        cache.clear();

        CaffeineDataKeyCache.CacheStatistics statsAfter = cache.getStats();
        assertEquals(0, statsAfter.estimatedSize);
    }

    public void testAdvancedMetrics() {
        // Generate cache hits and misses to test metrics
        cache.getDataKey("key1", () -> new SecretKeySpec(new byte[32], "AES"));
        cache.getDataKey("key1", () -> new SecretKeySpec(new byte[32], "AES")); // Hit
        cache.getDataKey("key2", () -> new SecretKeySpec(new byte[32], "AES")); // Miss

        CaffeineDataKeyCache.CacheStatistics stats = cache.getStats();

        // Verify Caffeine's advanced metrics
        assertTrue("Hit count should be positive", stats.hitCount >= 0);
        assertTrue("Miss count should be positive", stats.missCount >= 0);
        assertTrue("Hit rate should be between 0 and 1", stats.getHitRate() >= 0.0 && stats.getHitRate() <= 1.0);
        assertTrue("Average load time should be non-negative", stats.averageLoadTimeNanos >= 0);

        // Test toString() method
        String statsString = stats.toString();
        assertNotNull(statsString);
        assertTrue("Stats string should contain cache information", statsString.contains("CacheStats"));
    }

    public void testMultipleKeys() {
        AtomicInteger keyGenerationCount = new AtomicInteger(0);

        // Test multiple different keys
        Key key1 = cache.getDataKey("key1", () -> {
            keyGenerationCount.incrementAndGet();
            return new SecretKeySpec(new byte[32], "AES");
        });

        Key key2 = cache.getDataKey("key2", () -> {
            keyGenerationCount.incrementAndGet();
            return new SecretKeySpec(new byte[32], "AES");
        });

        Key key1Again = cache.getDataKey("key1", () -> {
            keyGenerationCount.incrementAndGet();
            return new SecretKeySpec(new byte[32], "AES");
        });

        assertNotNull(key1);
        assertNotNull(key2);
        assertNotNull(key1Again);
        assertSame(key1, key1Again); // Same key should be returned from cache
        assertEquals(2, keyGenerationCount.get()); // Only 2 keys should be generated
    }
}
