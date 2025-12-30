/*
 * Copyright 2012-2018 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jose4j.jwk;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import org.jose4j.http.SimpleResponse;
import org.jose4j.jwk.cache.JwksCache;
import org.jose4j.jwk.cache.InMemoryJwksCache;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a set of JSON Web Keys (typically public keys) published at an HTTPS URI.
 * Keys will be retrieved from the given location and cached based on the cache directive
 * headers and/or the {@link #setDefaultCacheDuration(long)}.
 * The keys are cached per {@code HttpsJwks} instance so your application will need to keep using
 * the same instance, however is appropriate for that application, to get the benefit of the caching.
 * This class, when used with {@code HttpsJwksVerificationKeyResolver}, can help facilitate the consuming side of
 * a key publication and rotation model like that which is described
 * in <a href="http://openid.net/specs/openid-connect-core-1_0.html#SigEnc">OpenID Connect, section 10</a>.
 *
 * @see org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver
 */
public class DefaultHttpsJwks
extends AbstractHttpsJwks
{
    private static final Logger log = LoggerFactory.getLogger(DefaultHttpsJwks.class);

    private volatile long defaultCacheDuration = 3600;  // seconds
    private volatile long retainCacheOnErrorDurationMills = 0;
    private volatile JwksCache cache = new InMemoryJwksCache();

    // used to stop multiple threads from refreshing in parallel
    private final ReentrantLock refreshLock = new ReentrantLock();
    
    private long refreshReprieveThreshold = 300L;

    /**
     * Create a new HttpsJwks that can be used to retrieve JWKs from the given location.
     * @param location the HTTPS URI of the JSON Web Key Set
     */
    public DefaultHttpsJwks(String location)
    {
    	super(location);
    }

    /**
     * Create a new HttpsJwks that can be used to retrieve JWKs from the given location
     * and uses the given cache implementation.
     * 
     * @param location the HTTPS URI of the JSON Web Key Set
     * @param jwksCache the cache implementation to use
     */
    public DefaultHttpsJwks(String location, JwksCache jwksCache)
	{
		super(location);
		setCache(jwksCache);
	}

    /**
     * The time period to cache the JWKs from the endpoint, if the cache directive
     * headers of the response are not present or indicate that the content should not be cached.
     * This is useful because the content of a JWKS endpoint should be cached in the vast majority
     * of situations and cache directive headers that indicate otherwise are likely a mistake or
     * misconfiguration.
     *
     * The default value, used when this method is not called, of the default cache duration is 3600 seconds (1 hour).
     *
     * @param defaultCacheDuration the length in seconds of the default cache duration
     */
    public void setDefaultCacheDuration(long defaultCacheDuration)
    {
        this.defaultCacheDuration = defaultCacheDuration;
    }

    /**
     * Sets the length of time, before trying again, to keep using the cache when an error occurs making the request to
     * the JWKS URI or parsing the response. When equal or less than zero, an exception will be thrown from {@link #getJsonWebKeys()}
     * when an error occurs. When larger than zero, the previously established cached list of keys (if it exists) will be used/returned
     * and another attempt to fetch the keys from the JWKS URI will not be made for the given duration.
     * The default value is 0.
     * @param retainCacheOnErrorDuration the length in seconds to keep using the cache when an error occurs before trying again
     */
    public void setRetainCacheOnErrorDuration(long retainCacheOnErrorDuration)
    {
        this.retainCacheOnErrorDurationMills = retainCacheOnErrorDuration * 1000L;
    }


    /**
     * Sets the period of time as a threshold for which a subsequent {@code refresh()} calls will use the cache and
     * not actually refresh from the JWKS endpoint/URL.
     * @param refreshReprieveThreshold the threshold time in milliseconds (probably should be a relatevily small value).
     *                                The default value, if unset is 300.
     */
    public void setRefreshReprieveThreshold(long refreshReprieveThreshold)
    {
        this.refreshReprieveThreshold = refreshReprieveThreshold;
    }

    public void setCache(JwksCache jwksCache)
    {
        if (jwksCache == null)
        {
            throw new IllegalArgumentException("JwksCache cannot be null.");
        }
        JwksCache.Entry existing = getCacheEntry();
        this.cache = jwksCache;
        if (existing.hasKeys())
        {
            updateCache(existing);
        }
    }

    /**
     * Gets the JSON Web Keys from the JWKS endpoint location or from local cache, if appropriate.
     * @return a list of JsonWebKeys
     * @throws JoseException if a problem is encountered parsing the JSON content into JSON Web Keys.
     * @throws IOException if a problem is encountered making the HTTP request.
     */
    public List<JsonWebKey> getJsonWebKeys() throws JoseException, IOException
    {
        final long now = System.currentTimeMillis();
        JwksCache.Entry entry = getCacheEntry();
        if (entry.getExpiresAt() > now)
        {
            // common case: keys are still good
            return entry.getKeys();
        }
        if (!refreshLock.tryLock())
        {
            // another thread is already refreshing, use cached keys for now (if not null)
            if (entry.hasKeys())
            {
                return entry.getKeys();
            }
            else
            {
                refreshLock.lock();
            }
        }
        // keys are expired and no other thread is refreshing them
        try
        {
            refresh();
            entry = getCacheEntry();
        }
        catch (Exception e)
        {
            if (retainCacheOnErrorDurationMills > 0 && entry.hasKeys())
            {
                JwksCache.Entry retained = new JwksCache.Entry(entry.getKeys(), now + retainCacheOnErrorDurationMills);
                updateCache(retained);
                entry = retained;
                log.info("Because of {} unable to refresh JWKS content from {} so will continue to use cached keys for more {} seconds until about {} -> {}", ExceptionHelp.toStringWithCauses(e), getLocation(), retainCacheOnErrorDurationMills/1000L, new Date(retained.getExpiresAt()), retained.getKeys());
            }
            else
            {
                throw e;
            }
        }
        finally
        {
            refreshLock.unlock();
        }
        return entry.getKeys();
    }


    /**
     * Forces a refresh of the cached JWKs from the JWKS endpoint.  With slight caveat/optimization that if the cache
     * age is less than {@code refreshReprieveThreshold} it will not actually force a refresh but use the cache instead.
     * @throws JoseException if an problem is encountered parsing the JSON content into JSON Web Keys.
     * @throws IOException if a problem is encountered making the HTTP request.
     */
    public void refresh() throws JoseException, IOException
    {
        refreshLock.lock();
        try
        {
            JwksCache.Entry currentEntry = getCacheEntry();
            long last = System.currentTimeMillis() - currentEntry.getCreated();

            if (last < refreshReprieveThreshold && currentEntry.hasKeys())
            {
                log.debug("NOT refreshing/loading JWKS from {} because it just happened {} mills ago", getLocation(), last);
            }
            else
            {
                log.debug("Refreshing/loading JWKS from {}", getLocation());
                SimpleResponse simpleResponse = performSimpleHttpGet();
                JsonWebKeySet jwks = new JsonWebKeySet(simpleResponse.getBody());
                List<JsonWebKey> keys = jwks.getJsonWebKeys();
                long cacheLife = getCacheLife(simpleResponse);
                if (cacheLife <= 0)
                {
                    log.debug("Will use default cache duration of {} seconds for content from {}", defaultCacheDuration, getLocation());
                    cacheLife = defaultCacheDuration;
                }
                long exp = System.currentTimeMillis() + (cacheLife * 1000L);
                log.debug("Updated JWKS content from {} will be cached for {} seconds until about {} -> {}", getLocation(), cacheLife, new Date(exp), keys);
                updateCache(new JwksCache.Entry(keys, exp));
            }
        } 
        finally
        {
            refreshLock.unlock();
        }
    }

    private JwksCache.Entry getCacheEntry()
    {
        JwksCache.Entry entry = cache.get(getLocation());
        return (entry == null) ? JwksCache.Entry.empty() : entry;
    }

    private void updateCache(JwksCache.Entry entry)
    {
        cache.put(getLocation(), entry);
    }

    static long getCacheLife(SimpleResponse response)
    {
        return getCacheLife(response, System.currentTimeMillis());
    }

    static long getCacheLife(SimpleResponse response, long currentTime)
    {
        // start with expires
        long expires = HttpsJwks.getExpires(response);
        long life = (expires - currentTime) / 1000L;

        // but Cache-Control takes precedence
        List<String> values = HttpsJwks.getHeaderValues(response, "cache-control");
        for (String value : values)
        {
            try
            {
                // only care about the max-age value so just pull it out rather than parsing the whole header
                value = (value == null) ? "" : value.toLowerCase();
                int indexOfMaxAge = value.indexOf("max-age");
                int indexOfComma = value.indexOf(',', indexOfMaxAge);
                int end = indexOfComma == -1 ? value.length() : indexOfComma;
                String part = value.substring(indexOfMaxAge, end);
                part = part.substring(part.indexOf('=') + 1);
                part = part.trim();
                life = Long.parseLong(part);
                break;
            }
            catch (Exception e)
            {
                // ignore it
            }

        }

        return life;
    }

}
