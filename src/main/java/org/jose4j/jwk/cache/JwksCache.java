package org.jose4j.jwk.cache;

import java.util.Collections;
import java.util.List;

import org.jose4j.jwk.JsonWebKey;

/**
 * Abstraction over the storage of JWKS responses so that the cached key material can be
 * externalized or shared across instances.
 */
public interface JwksCache
{
    /**
     * Retrieves the cache entry identified by {@code key}.
     * @param key identifier for the JWKS cache entry (usually the JWKS URL).
     * @return the cache entry or {@code null} if nothing is cached.
     */
    Entry get(String key);

    /**
     * Stores the cache entry identified by {@code key}.
     * @param key identifier for the JWKS cache entry (usually the JWKS URL).
     * @param entry cache entry to store; never {@code null}.
     */
    void put(String key, Entry entry);

    /**
     * Represents cached JWKS data along with the associated expiration metadata.
     */
    public final class Entry
    {
        private static final Entry EMPTY = new Entry(Collections.<JsonWebKey>emptyList(), 0, 0);

        private final List<JsonWebKey> keys;
        private final long expiresAt;
        private final long created;

        /**
         * Creates a cache entry using the provided {@code keys} and expiration time.
         * @param keys keys returned by the JWKS endpoint.
         * @param expiresAt the absolute expiration time in milliseconds since epoch.
         */
        public Entry(List<JsonWebKey> keys, long expiresAt)
        {
            this(keys, expiresAt, System.currentTimeMillis());
        }

        private Entry(List<JsonWebKey> keys, long expiresAt, long created)
        {
            this.keys = (keys == null) ? Collections.<JsonWebKey>emptyList() : keys;
            this.expiresAt = expiresAt;
            this.created = created;
        }

        public static Entry empty()
        {
            return EMPTY;
        }

        public List<JsonWebKey> getKeys()
        {
            return keys;
        }

        public long getExpiresAt()
        {
            return expiresAt;
        }

        public long getCreated()
        {
            return created;
        }

        public boolean hasKeys()
        {
            return !keys.isEmpty();
        }
    }
}
