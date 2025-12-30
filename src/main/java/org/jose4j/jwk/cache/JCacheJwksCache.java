package org.jose4j.jwk.cache;

import javax.cache.Cache;
import javax.cache.CacheManager;

/**
 * {@link JwksCache} implementation backed by a JCache provider.
 */
public class JCacheJwksCache implements JwksCache
{
    private final Cache<String, Entry> cache;

    /**
     * Creates the cache wrapper using the provided {@link Cache} reference.
     * @param cache the cache instance that will store JWKS responses
     */
    public JCacheJwksCache(Cache<String, Entry> cache)
    {
        if (cache == null)
        {
            throw new IllegalArgumentException("cache cannot be null.");
        }
        this.cache = cache;
    }

    /**
     * Looks up the named cache from the {@link CacheManager}.
     * @param cacheManager cache manager configured with the desired provider.
     * @param cacheName the cache name.
     */
    public JCacheJwksCache(CacheManager cacheManager, String cacheName)
    {
        this(resolve(cacheManager, cacheName));
    }

    private static Cache<String, Entry> resolve(CacheManager cacheManager, String cacheName)
    {
        if (cacheManager == null)
        {
            throw new IllegalArgumentException("cacheManager cannot be null.");
        }
        if (cacheName == null)
        {
            throw new IllegalArgumentException("cacheName cannot be null.");
        }

        Cache<String, Entry> cache = cacheManager.getCache(cacheName, String.class, Entry.class);
        if (cache == null)
        {
            throw new IllegalArgumentException("No cache named " + cacheName + " found in the provided CacheManager.");
        }
        return cache;
    }

    @Override
    public Entry get(String key)
    {
        return cache.get(key);
    }

    @Override
    public void put(String key, Entry entry)
    {
        cache.put(key, entry);
    }
}
