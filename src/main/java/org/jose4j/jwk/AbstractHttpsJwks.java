package org.jose4j.jwk;

import java.io.IOException;

import org.jose4j.http.Get;
import org.jose4j.http.SimpleGet;
import org.jose4j.http.SimpleResponse;

public abstract class AbstractHttpsJwks
implements HttpsJwks
{
    private final String location;
    private volatile SimpleGet simpleHttpGet = new Get();

    /**
     * Create a new HttpsJwks that cab be used to retrieve JWKs from the given location.
     * @param location the HTTPS URI of the JSON Web Key Set
     */
    protected AbstractHttpsJwks(String location)
    {
        this.location = location;
    }

    /**
     * Sets the SimpleGet instance to use when making the HTTP GET request to the JWKS location.
     * By default a new instance of {@link org.jose4j.http.Get} is used. This method should be used
     * right after construction, if a different implementation of {@link org.jose4j.http.SimpleGet}
     * or non-default configured instance of {@link org.jose4j.http.Get} is needed.
     * @param simpleHttpGet the instance of the implementation of SimpleGet to use
     */
    public void setSimpleHttpGet(SimpleGet simpleHttpGet)
    {
        this.simpleHttpGet = simpleHttpGet;
    }

    /**
     * Gets the location of the JWKS endpoint/URL.
     * @return the location
     */
    public String getLocation()
    {
        return location;
    }

	protected SimpleResponse performSimpleHttpGet()
	throws IOException
	{
		return simpleHttpGet.get(location);
	}
}
