# TTL-Based Data Key Caching Feature

## Overview

This feature implements a Time-To-Live (TTL) based caching system for data keys in the OpenSearch storage encryption plugin. Instead of keeping decrypted data keys in memory indefinitely, the system now:

- Caches decrypted data keys for a configurable TTL (default: 5 minutes)
- Automatically refreshes keys from KMS when they expire
- Provides thread-safe access with minimal performance impact
- Supports automatic eviction and size limits

## Configuration

### Settings

Two new configuration settings are available:

```yaml
# TTL for cached data keys in seconds (default: 300 = 5 minutes)
kms.data_key_cache_ttl_seconds: 300

# Maximum number of keys to cache (default: 100, set to 0 for unlimited)
kms.data_key_cache_max_size: 100
```

### Example Configuration

```yaml
# opensearch.yml
kms.data_key_cache_ttl_seconds: 600  # 10 minutes
kms.data_key_cache_max_size: 50      # Cache up to 50 keys
```

## Architecture

### Components

1. **DataKeyCache**: Core caching implementation
   - TTL-based expiration
   - LRU eviction when size limit reached
   - Thread-safe concurrent access
   - Background cleanup of expired entries
   - Graceful error handling with fallback

2. **DefaultKeyIvResolver**: Updated to use the cache
   - Transparent integration with existing code
   - Automatic KMS calls on cache miss
   - Uses keyProvider.getKeyId() as cache key

3. **CryptoDirectoryFactory**: Passes configuration to resolver
   - Reads settings from index/node configuration
   - Creates cache-enabled resolvers

### Key Features

- **Transparent Operation**: Existing code continues to work without changes
- **Thread Safety**: Uses ReentrantReadWriteLock for cache operations
- **Error Resilience**: Returns expired keys if KMS refresh fails
- **Monitoring**: Provides cache statistics for observability
- **Resource Management**: Automatic cleanup of expired entries and proper shutdown

## Usage

### Basic Usage

The caching is transparent - existing code continues to work:

```java
// This now uses TTL-based caching internally
Key dataKey = keyIvResolver.getDataKey();
```

### Advanced Usage

For monitoring and management:

```java
DefaultKeyIvResolver resolver = new DefaultKeyIvResolver(directory, provider, keyProvider, settings);

// Get cache statistics
DataKeyCache.CacheStats stats = resolver.getCacheStats();
System.out.println("Cache entries: " + stats.totalEntries);
System.out.println("Expired entries: " + stats.expiredEntries);

// Manually invalidate a key
resolver.invalidateKey("specific-key-id");

// Clean shutdown
resolver.shutdown();
```

## Performance Impact

### Benefits

- **Reduced KMS Calls**: Keys are cached for the TTL duration
- **Improved Latency**: Cache hits avoid expensive KMS decrypt operations  
- **Better Throughput**: Multiple threads can access cached keys concurrently

### Overhead

- **Memory Usage**: Small overhead per cached key (~few KB per entry)
- **Background Thread**: Single daemon thread for cleanup (minimal impact)
- **Synchronization**: Minimal locking overhead for cache operations

## Security Considerations

- **Memory Security**: Keys are held in memory for TTL duration only
- **Thread Safety**: Secure concurrent access to sensitive key material
- **Error Handling**: Expired keys used as fallback only in failure cases
- **Resource Cleanup**: Automatic cleanup prevents memory leaks

## Monitoring

### Logs

The system provides detailed logging:

```
INFO  DataKeyCache - Cache hit for keyId: my-key-123
INFO  DataKeyCache - Cache miss for keyId: my-key-123, refreshing from KMS
WARN  DataKeyCache - Using expired key as fallback for keyId: my-key-123
ERROR DataKeyCache - Failed to refresh data key for keyId: my-key-123
```

### Metrics

Cache statistics available programmatically:

- `totalEntries`: Current number of cached keys
- `expiredEntries`: Number of expired but not yet cleaned entries
- `ttlMillis`: Configured TTL in milliseconds
- `maxSize`: Maximum cache size limit

## Testing

Comprehensive test coverage includes:

- Cache hit/miss scenarios
- TTL expiration behavior
- Concurrent access safety
- Error handling and fallback
- Cache invalidation and cleanup
- Statistics accuracy

Run tests with:
```bash
./gradlew test --tests DataKeyCacheTest
```

## Migration

### From Previous Version

No changes required - the caching is automatically enabled with default settings (5-minute TTL, 100 key limit).

### Rollback

To disable caching, set TTL to a very high value:
```yaml
kms.data_key_cache_ttl_seconds: 86400  # 24 hours (effectively disabled)
```

## Troubleshooting

### Common Issues

1. **High KMS Usage**: Check if TTL is too low
   - Solution: Increase `kms.data_key_cache_ttl_seconds`

2. **Memory Usage**: Cache growing too large
   - Solution: Reduce `kms.data_key_cache_max_size`

3. **KMS Failures**: Keys not refreshing
   - Check: KMS connectivity and permissions
   - Fallback: System continues with expired keys

### Debug Logging

Enable debug logging for detailed cache behavior:
```yaml
logger.org.opensearch.index.store.iv.DataKeyCache: DEBUG
```

## Implementation Details

### Cache Key Strategy

- Primary: Uses `keyProvider.getKeyId()` from the MasterKeyProvider
- Fallback: Uses "default" if keyId not available
- This allows multiple keys to be cached if different key providers are used

### Expiration Logic

- Time-based expiration using `System.currentTimeMillis()`
- Background cleanup thread runs every 30 seconds
- Double-checked locking for thread-safe refresh

### Error Handling

- KMS failures during refresh return expired keys as fallback
- Comprehensive logging for debugging
- Graceful degradation maintains system availability

## Future Enhancements

Potential improvements for future versions:

- Configurable cleanup frequency
- Metrics integration with OpenSearch monitoring
- Cache warming strategies
- Key rotation event handling
- Regional failover support
