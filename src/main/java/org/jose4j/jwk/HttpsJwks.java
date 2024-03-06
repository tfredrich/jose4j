package org.jose4j.jwk;

import java.io.IOException;
import java.text.DateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.jose4j.http.SimpleGet;
import org.jose4j.http.SimpleResponse;
import org.jose4j.lang.JoseException;

public interface HttpsJwks {

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
	void setDefaultCacheDuration(long defaultCacheDuration);

	/**
	 * Sets the length of time, before trying again, to keep using the cache when an error occurs making the request to
	 * the JWKS URI or parsing the response. When equal or less than zero, an exception will be thrown from {@link #getJsonWebKeys()}
	 * when an error occurs. When larger than zero, the previously established cached list of keys (if it exists) will be used/returned
	 * and another attempt to fetch the keys from the JWKS URI will not be made for the given duration.
	 * The default value is 0.
	 * @param retainCacheOnErrorDuration the length in seconds to keep using the cache when an error occurs before trying again
	 */
	void setRetainCacheOnErrorDuration(long retainCacheOnErrorDuration);

	/**
	 * Sets the SimpleGet instance to use when making the HTTP GET request to the JWKS location.
	 * By default a new instance of {@link org.jose4j.http.Get} is used. This method should be used
	 * right after construction, if a different implementation of {@link org.jose4j.http.SimpleGet}
	 * or non-default configured instance of {@link org.jose4j.http.Get} is needed.
	 * @param simpleHttpGet the instance of the implementation of SimpleGet to use
	 */
	void setSimpleHttpGet(SimpleGet simpleHttpGet);

	/**
	 * Gets the location of the JWKS endpoint/URL.
	 * @return the location
	 */
	String getLocation();

	/**
	 * Sets the period of time as a threshold for which a subsequent {@code refresh()} calls will use the cache and
	 * not actually refresh from the JWKS endpoint/URL.
	 * @param refreshReprieveThreshold the threshold time in milliseconds (probably should be a relatevily small value).
	 *                                The default value, if unset is 300.
	 */
	void setRefreshReprieveThreshold(long refreshReprieveThreshold);

	/**
	 * Gets the JSON Web Keys from the JWKS endpoint location or from local cache, if appropriate.
	 * @return a list of JsonWebKeys
	 * @throws JoseException if a problem is encountered parsing the JSON content into JSON Web Keys.
	 * @throws IOException if a problem is encountered making the HTTP request.
	 */
	List<JsonWebKey> getJsonWebKeys() throws JoseException, IOException;

	/**
	 * Forces a refresh of the cached JWKs from the JWKS endpoint.  With slight caveat/optimization that if the cache
	 * age is less than {@code refreshReprieveThreshold} it will not actually force a refresh but use the cache instead.
	 * @throws JoseException if an problem is encountered parsing the JSON content into JSON Web Keys.
	 * @throws IOException if a problem is encountered making the HTTP request.
	 */
	void refresh() throws JoseException, IOException;

    static long getDateHeaderValue(SimpleResponse response, String headerName, long defaultValue)
    {
        List<String> values = getHeaderValues(response, headerName);
        for (String value : values)
        {
            try
            {
                if (!value.endsWith("GMT"))
                {
                    value += " GMT";
                }

                return Date.parse(value);
            }
            catch (Exception e)
            {
                // ignore it
            }
        }
        return defaultValue;
    }

    static List<String> getHeaderValues(SimpleResponse response, String headerName)
    {
        List<String> values = response.getHeaderValues(headerName);
        return  (values == null) ? Collections.<String>emptyList() : values;
    }

    static long getExpires(SimpleResponse response)
    {
        return getDateHeaderValue(response, "expires", 0);
    }
}