/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.index.store.iv;

import java.security.Key;
import java.util.Locale;

/**
 * Immutable holder for a data key with its refresh timestamp.
 * Used for TTL-based key management in encryption operations.
 * 
 * @opensearch.internal
 */
public final class DataKeyHolder {

    private final Key dataKey;
    private final long refreshTime;

    /**
     * Creates a new DataKeyHolder with the specified key and refresh time.
     *
     * @param dataKey the encryption key
     * @param refreshTime when this key was last refreshed (System.currentTimeMillis())
     * @throws IllegalArgumentException if dataKey is null
     */
    public DataKeyHolder(Key dataKey, long refreshTime) {
        if (dataKey == null) {
            throw new IllegalArgumentException("dataKey cannot be null");
        }
        this.dataKey = dataKey;
        this.refreshTime = refreshTime;
    }

    /**
     * Returns the data key.
     *
     * @return the encryption key
     */
    public Key getDataKey() {
        return dataKey;
    }

    /**
     * Returns the refresh timestamp.
     *
     * @return when this key was last refreshed (milliseconds since epoch)
     */
    public long getRefreshTime() {
        return refreshTime;
    }

    /**
     * Checks if this key needs pre-emptive refresh based on TTL and threshold.
     *
     * @param ttlMillis the total TTL for the key in milliseconds
     * @param refreshThreshold the threshold (0.0 to 1.0) at which to trigger refresh
     * @return true if refresh should be triggered
     * @throws IllegalArgumentException if refreshThreshold is not between 0.0 and 1.0
     */
    public boolean needsRefresh(long ttlMillis, double refreshThreshold) {
        if (refreshThreshold < 0.0 || refreshThreshold > 1.0) {
            throw new IllegalArgumentException("refreshThreshold must be between 0.0 and 1.0");
        }

        long currentTime = System.currentTimeMillis();
        long refreshAge = (long) (ttlMillis * refreshThreshold);
        return (currentTime - refreshTime) > refreshAge;
    }

    /**
     * Checks if this key has expired based on TTL.
     *
     * @param ttlMillis the TTL for the key in milliseconds
     * @return true if the key has exceeded its TTL
     */
    public boolean isExpired(long ttlMillis) {
        long currentTime = System.currentTimeMillis();
        return (currentTime - refreshTime) > ttlMillis;
    }

    /**
     * Returns the age of this key in milliseconds.
     *
     * @return milliseconds since this key was refreshed
     */
    public long getAge() {
        return System.currentTimeMillis() - refreshTime;
    }

    @Override
    public String toString() {
        return String.format(Locale.ROOT, "DataKeyHolder{refreshTime=%d, age=%dms}", refreshTime, getAge());
    }
}
