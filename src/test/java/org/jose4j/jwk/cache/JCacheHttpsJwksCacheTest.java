package org.jose4j.jwk.cache;

import static org.junit.Assert.assertSame;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.configuration.CacheEntryListenerConfiguration;
import javax.cache.configuration.Configuration;
import javax.cache.integration.CompletionListener;
import javax.cache.processor.EntryProcessor;
import javax.cache.processor.EntryProcessorException;
import javax.cache.processor.EntryProcessorResult;
import javax.cache.spi.CachingProvider;

import org.jose4j.jwk.JsonWebKey;
import org.junit.Test;

public class JCacheHttpsJwksCacheTest
{
    @Test
    public void delegatesToProvidedCache()
    {
        StubCache cache = new StubCache("direct");
        JCacheJwksCache jwksCache = new JCacheJwksCache(cache);

        JwksCache.Entry entry = new JwksCache.Entry(Collections.<JsonWebKey>emptyList(), 1000L);
        jwksCache.put("foo", entry);
        assertSame(entry, jwksCache.get("foo"));
    }

    @Test
    public void resolvesCacheFromManager()
    {
        StubCache cache = new StubCache("managed");
        StubCacheManager cacheManager = new StubCacheManager(cache);

        JCacheJwksCache jwksCache = new JCacheJwksCache(cacheManager, "managed");
        JwksCache.Entry entry = new JwksCache.Entry(Collections.<JsonWebKey>emptyList(), 42L);
        jwksCache.put("bar", entry);
        assertSame(entry, jwksCache.get("bar"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void failsWhenCacheMissing()
    {
        StubCacheManager cacheManager = new StubCacheManager(null);
        new JCacheJwksCache(cacheManager, "missing");
    }

    private static final class StubCache implements Cache<String, JwksCache.Entry>
    {
        private final String name;
        private final Map<String, JwksCache.Entry> store = new HashMap<>();
        private boolean closed;

        StubCache(String name)
        {
            this.name = name;
        }

        private void checkClosed()
        {
            if (closed)
            {
                throw new IllegalStateException("cache closed");
            }
        }

        @Override
        public JwksCache.Entry get(String key)
        {
            checkClosed();
            return store.get(key);
        }

        @Override
        public Map<String, JwksCache.Entry> getAll(Set<? extends String> keys)
        {
            checkClosed();
            Map<String, JwksCache.Entry> result = new HashMap<>();
            for (String key : keys)
            {
                if (store.containsKey(key))
                {
                    result.put(key, store.get(key));
                }
            }
            return result;
        }

        @Override
        public boolean containsKey(String key)
        {
            checkClosed();
            return store.containsKey(key);
        }

        @Override
        public void loadAll(Set<? extends String> keys, boolean replaceExistingValues, CompletionListener completionListener)
        {
            throw new UnsupportedOperationException("loadAll");
        }

        @Override
        public void put(String key, JwksCache.Entry value)
        {
            checkClosed();
            store.put(key, value);
        }

        @Override
        public JwksCache.Entry getAndPut(String key, JwksCache.Entry value)
        {
            checkClosed();
            return store.put(key, value);
        }

        @Override
        public void putAll(Map<? extends String, ? extends JwksCache.Entry> map)
        {
            checkClosed();
            store.putAll(map);
        }

        @Override
        public boolean putIfAbsent(String key, JwksCache.Entry value)
        {
            checkClosed();
            return store.putIfAbsent(key, value) == null;
        }

        @Override
        public boolean remove(String key)
        {
            checkClosed();
            return store.remove(key) != null;
        }

        @Override
        public boolean remove(String key, JwksCache.Entry oldValue)
        {
            checkClosed();
            if (store.containsKey(key) && store.get(key).equals(oldValue))
            {
                store.remove(key);
                return true;
            }
            return false;
        }

        @Override
        public JwksCache.Entry getAndRemove(String key)
        {
            checkClosed();
            return store.remove(key);
        }

        @Override
        public void removeAll(Set<? extends String> keys)
        {
            checkClosed();
            for (String key : keys)
            {
                store.remove(key);
            }
        }

        @Override
        public void removeAll()
        {
            checkClosed();
            store.clear();
        }

        @Override
        public void clear()
        {
            removeAll();
        }

        @Override
        public <C extends Configuration<String, JwksCache.Entry>> C getConfiguration(Class<C> clazz)
        {
            throw new UnsupportedOperationException("getConfiguration");
        }

        @Override
        public <T> T invoke(String key, EntryProcessor<String, JwksCache.Entry, T> entryProcessor, Object... arguments)
                throws EntryProcessorException
        {
            throw new UnsupportedOperationException("invoke");
        }

        @Override
        public <T> Map<String, EntryProcessorResult<T>> invokeAll(Set<? extends String> keys,
                EntryProcessor<String, JwksCache.Entry, T> entryProcessor, Object... arguments)
        {
            throw new UnsupportedOperationException("invokeAll");
        }

        @Override
        public String getName()
        {
            return name;
        }

        @Override
        public CacheManager getCacheManager()
        {
            return null;
        }

        @Override
        public void close()
        {
            closed = true;
            store.clear();
        }

        @Override
        public boolean isClosed()
        {
            return closed;
        }

        @Override
        public <T> T unwrap(Class<T> clazz)
        {
            if (clazz.isInstance(this))
            {
                return clazz.cast(this);
            }
            throw new IllegalArgumentException("Unsupported unwrap: " + clazz);
        }

        @Override
        public void registerCacheEntryListener(CacheEntryListenerConfiguration<String, JwksCache.Entry> cacheEntryListenerConfiguration)
        {
            throw new UnsupportedOperationException("registerCacheEntryListener");
        }

        @Override
        public void deregisterCacheEntryListener(CacheEntryListenerConfiguration<String, JwksCache.Entry> cacheEntryListenerConfiguration)
        {
            throw new UnsupportedOperationException("deregisterCacheEntryListener");
        }

        @Override
        public Iterator<Entry<String, JwksCache.Entry>> iterator()
        {
            checkClosed();
            return Collections.<Entry<String, JwksCache.Entry>>emptySet().iterator();
        }

        @Override
        public JwksCache.Entry getAndReplace(String key, JwksCache.Entry value)
        {
            checkClosed();
            if (store.containsKey(key))
            {
                return store.put(key, value);
            }
            return null;
        }

        @Override
        public boolean replace(String key, JwksCache.Entry oldValue, JwksCache.Entry newValue)
        {
            checkClosed();
            if (store.containsKey(key) && store.get(key).equals(oldValue))
            {
                store.put(key, newValue);
                return true;
            }
            return false;
        }

        @Override
        public boolean replace(String key, JwksCache.Entry value)
        {
            checkClosed();
            if (store.containsKey(key))
            {
                store.put(key, value);
                return true;
            }
            return false;
        }
    }

    private static final class StubCacheManager implements CacheManager
    {
        private final Cache<String, JwksCache.Entry> cache;

        StubCacheManager(Cache<String, JwksCache.Entry> cache)
        {
            this.cache = cache;
        }

        @Override
        public CachingProvider getCachingProvider()
        {
            return null;
        }

        @Override
        public java.net.URI getURI()
        {
            return null;
        }

        @Override
        public ClassLoader getClassLoader()
        {
            return getClass().getClassLoader();
        }

        @Override
        public Properties getProperties()
        {
            return new Properties();
        }

        @Override
        public <K, V, C extends Configuration<K, V>> Cache<K, V> createCache(String cacheName, C configuration)
        {
            throw new UnsupportedOperationException("createCache");
        }

        @SuppressWarnings("unchecked")
        @Override
        public <K, V> Cache<K, V> getCache(String cacheName, Class<K> keyType, Class<V> valueType)
        {
            return (Cache<K, V>) cache;
        }

        @SuppressWarnings("unchecked")
        @Override
        public <K, V> Cache<K, V> getCache(String cacheName)
        {
            return (Cache<K, V>) cache;
        }

        @Override
        public Iterable<String> getCacheNames()
        {
            return Collections.singleton("managed");
        }

        @Override
        public void destroyCache(String cacheName)
        {
            throw new UnsupportedOperationException("destroyCache");
        }

        @Override
        public void enableManagement(String cacheName, boolean enabled)
        {
            throw new UnsupportedOperationException("enableManagement");
        }

        @Override
        public void enableStatistics(String cacheName, boolean enabled)
        {
            throw new UnsupportedOperationException("enableStatistics");
        }

        @Override
        public void close()
        {
            // no-op
        }

        @Override
        public boolean isClosed()
        {
            return false;
        }

        @Override
        public <T> T unwrap(Class<T> clazz)
        {
            throw new UnsupportedOperationException("unwrap");
        }
    }
}
