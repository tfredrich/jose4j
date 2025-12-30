package org.jose4j.jwk.cache;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Default in-memory implementation used when no external cache backend is configured.
 */
public class InMemoryJwksCache implements JwksCache
{
    private final ConcurrentMap<String, Entry> cache = new ConcurrentHashMap<>();

    @Override
    public Entry get(String key)
    {
        return cache.get(key);
    }

    @Override
    public void put(String key, Entry entry)
    {
        if (entry == null)
        {
            cache.remove(key);
        }
        else
        {
            cache.put(key, entry);
        }
    }
}
