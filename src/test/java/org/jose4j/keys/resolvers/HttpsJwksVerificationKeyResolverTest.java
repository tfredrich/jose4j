/*
 * Copyright 2012-2017 Brian Campbell
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
package org.jose4j.keys.resolvers;

import org.jose4j.http.Get;
import org.jose4j.http.Response;
import org.jose4j.http.SimpleResponse;
import org.jose4j.jwk.*;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 *
 */
public class HttpsJwksVerificationKeyResolverTest
{
	private static final Logger log = LoggerFactory.getLogger(HttpsJwksVerificationKeyResolverTest.class);
	
    @Test
    public void simpleKeyFoundThenNotFoundAndRefreshToFindAndThenCantFind() throws Exception
    {
        String firstJkwsJson = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k1\",\"x\":\"1u9oeAkLQJcAnrv_m4fupf-lF43yFqmNjMsrukKDhEE\",\"y\":\"RG0cyWzinUl8NpfVVw2DqfH6zRqU_yF6aL1swssNv4E\",\"crv\":\"P-256\"}]}";
        String secondJwkJson = "{\"keys\":[{\"kty\":\"EC\",\"kid\":\"k2\",\"x\":\"865vGRGnwRFf1YWFI-ODhHkQwYs7dc9VlI8zleEUqyA\",\"y\":\"W-7d1hvHrhNqNGVVNZjTUopIdaegL3jEjWOPX284AOk\",\"crv\":\"P-256\"}]}";

        JsonWebKeySet jwks = new JsonWebKeySet(firstJkwsJson);
        JsonWebKey k1 = jwks.getJsonWebKeys().iterator().next();

        jwks = new JsonWebKeySet(secondJwkJson);
        JsonWebKey k2 = jwks.getJsonWebKeys().iterator().next();

        String location = "https://www.example.org/";
        HttpsJwks httpsJkws = new DefaultHttpsJwks(location);

        Get mockGet = mock(Get.class);
        Map<String,List<String>> headers = Collections.emptyMap();
        SimpleResponse ok1 = new Response(200, "OK", headers, firstJkwsJson);
        SimpleResponse ok2 = new Response(200, "OK", headers, secondJwkJson);
        when(mockGet.get(location)).thenReturn(ok1, ok2);

        httpsJkws.setRefreshReprieveThreshold(0);
        httpsJkws.setSimpleHttpGet(mockGet);

        HttpsJwksVerificationKeyResolver resolver = new HttpsJwksVerificationKeyResolver(httpsJkws);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("k1");
        Key key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
        assertThat(key, equalTo(k1.getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("k1");
        key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
        assertThat(key, equalTo(k1.getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("k1");
        key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
        assertThat(key, equalTo(k1.getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("k2");
        key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
        assertThat(key, equalTo(k2.getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("k2");
        key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
        assertThat(key, equalTo(k2.getKey()));

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("nope");
        try
        {
            key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
            fail("shouldn't have resolved a key but got " + key);
        }
        catch (UnresolvableKeyException e)
        {
        	log.debug("this was expected and is okay: {}", e.toString() );
            assertFalse("do you really need UnresolvableKeyException inside a UnresolvableKeyException?", e.getCause() instanceof UnresolvableKeyException);
        }
    }

    @Test
    public void testAnEx() throws Exception
    {
        String location = "https://www.example.org/";

        Get mockGet = mock(Get.class);
        when(mockGet.get(location)).thenThrow(new IOException(location + "says 'no GET for you!'"));
        HttpsJwks httpsJkws = new DefaultHttpsJwks(location);
        httpsJkws.setSimpleHttpGet(mockGet);
        HttpsJwksVerificationKeyResolver resolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setKeyIdHeaderValue("nope");
        try
        {
            Key key = resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
            fail("shouldn't have resolved a key but got " + key);

        }
        catch (UnresolvableKeyException e)
        {
            log.debug("this was expected and is okay: {}", e.toString());
        }
    }

    @Test
    public void selectWithVerifySignatureDisambiguate() throws Exception
    {
        JsonWebSignature jwsWith1stEC = new JsonWebSignature();
        jwsWith1stEC.setCompactSerialization("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "04tBvYG5QeY8lniGnkZNHMW8b0OPCN6XHuK9g8fsOz8uA_r0Yk-biMkWG7ltOMCFSiiPvEu7jNWfWbk0v-hWOg");

        JsonWebSignature jwsWith2ndEC = new JsonWebSignature();
        jwsWith2ndEC.setCompactSerialization("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "uIRIFrhftV39qJNOdaL8LwrK1prIJIHsP7Gn6jJAVbE2Mx4IkwGzBXDLKMulM1IvKElmSyK_KBg8afywcxoApA");

        JsonWebSignature jwsWith3rdEC = new JsonWebSignature();
        jwsWith3rdEC.setCompactSerialization("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "21eYfC_ZNf1FQ1Dtvj4rUiM9jYPgf1zJfeE_b2fclgu36KAN141ICqVjNxQqlK_7Wbct_FDxgyHvej_LEigb2Q");

        JsonWebSignature jwsWith1stRsa = new JsonWebSignature();
        jwsWith1stRsa.setCompactSerialization("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "aECOQefwSdjN1Sj7LWRBV3m1uuHOFDL02nFxMWifACMELrdYZ2i9W_c6Co0SQoJ5HUE0otA8b2mXQBxJ-azetXT4YiJYBpNbKk_H52KOUWvLoOYNwrTKylWjoTprAQpCr9KQWvjn3xrCoers4N63iCC1D9mKOCrUWFzDy-" +
                "-inXDj-5VlLWfCUhu8fjx_lotgUYQVD03Rm06P3OWGz5G_oksJ7VpxDDRAYt7zROgmjFDpSWmAtNEKoAlRTeKnZZSN0R71gznBsofs-jJ8zF0QcFOuAfqHVaDWnKwqS0aduZXm0s7rH61e4OwtQdTtFZqCPldUxlfC7uzvLhxgXrdLew");

        JsonWebSignature jwsWith2ndRSA = new JsonWebSignature();
        jwsWith2ndRSA.setCompactSerialization("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "pgBu9S8g7MC2BN9YNlWD9JhjzWbQVjqpmErW4hMFncKD8bUidIbMBJSI3URXvnMJrLrAC5eB2gb6DccF_txQaqX1X81JbTSdQ44_P1W-1uIIkfIXUvM6OXv48W-CPm8xGuetQ1ayHgU_1ljtdkbdUHZ6irgaeIrFMgZX0J" +
                "db9Eydnfhwvno2oGk3y6ruq2KgKABIdzgvJXfwdOFGn1z0CxwQSVDkFRLsMsBljTwfTd0v3G8OXT8WRMZMGVyAgtKVu3XJyrPNntVqrzdgQQma6S06Y9J9V9t0AlgEAn2B4TqMxYcu1Tjr7bBL_v83zEXhbdcFBYLfJg-LY5wE6rA-dA");


        JsonWebSignature jwsWithUnknownEC = new JsonWebSignature();
        jwsWithUnknownEC.setCompactSerialization("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzOTEyNywiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "UE4B0IVPRip-3TDKhNAadCuj_Bf5PlEAn9K94Zd7mP25WNZwxDbQpDElZTZSp-3ngPqQyPGj27emYRHhOnFSAQ");

        JsonWebSignature jwsWith384EC = new JsonWebSignature();
        jwsWith384EC.setCompactSerialization("eyJhbGciOiJFUzM4NCJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzOTIzMSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "NyRtG_eFmMLQ0XkW5kvdSpzYsm6P5M3U8EBFKIhD-jw8E7FOYw9PZ3_o1PWuLWH3XeArZMW7-bAIVxo2bHqJsSUtB6Tf0NWPtCpUF2c1vbuRXEXkGrCUmc4sKyOBjimC");

        String firstJkwsJson =
                "{\"keys\":[" +
                        "{\"kty\":\"EC\",\"x\":\"yd4yK8EJWNY-fyB0veOTNqDt_HqpPa45VTSJjIiI8vM\",\"y\":\"UspqZi9nPaUwBY8kD6MPDHslh5f6UMnAiXsg1l3i6UM\",\"crv\":\"P-256\"}," +
                        "{\"kty\":\"EC\",\"x\":\"3WPq7AnMkQekA1ogYFqNS5NBOXPs68xadKvtsn4pgas\",\"y\":\"CEvQFmGwKv96TQYRrgS-nFl9xWfN8PuLnIwBVmtpfp0\",\"crv\":\"P-256\"}" +
                        "]}";

        String secondJwksJson =
                "{\"keys\":[" +
                        "{\"kty\":\"EC\",\"x\":\"yd4yK8EJWNY-fyB0veOTNqDt_HqpPa45VTSJjIiI8vM\",\"y\":\"UspqZi9nPaUwBY8kD6MPDHslh5f6UMnAiXsg1l3i6UM\",\"crv\":\"P-256\"}," +
                        "{\"kty\":\"EC\",\"x\":\"3WPq7AnMkQekA1ogYFqNS5NBOXPs68xadKvtsn4pgas\",\"y\":\"CEvQFmGwKv96TQYRrgS-nFl9xWfN8PuLnIwBVmtpfp0\",\"crv\":\"P-256\"}," +
                        "{\"kty\":\"EC\",\"x\":\"DUYwuVdWtzfd2nkfQ7YEE_3ORRv3o0PYX39qNGVNlyA\",\"y\":\"qxxvewtvj61pnGDS7hWZ026oZehJxtQO3-9oVa6YdT8\",\"crv\":\"P-256\"}," +
                        "{\"kty\":\"RSA\",\"n\":\"mGOTvaqxy6AlxHXJFqQc5WSfH3Mjso0nlleF4a1ebSMgnqpmK_s6BSP0v9CyKyn_sBNpsH6dlOsks4qwb88SdvoWpMo2ZCIt8YlefirEaT9J8OQycxMv" +
                        "k7U1t6vCyN8Z68FrwhzzsmnNI_GC723OfMhcEZiRGNRJadPCMPfY3q5PgRrCjUS4v2hQjaicDpZETgbGxWNuNiIPk2CGhG3LJIUX4rx5zrFPQuUKH2Z1zH4E39i3Ab0WBATY0" +
                        "warvlImI5_rT-uCvvepnaQ6Mc4ImpS3anLNjfPlaNVajl5aRuzzRO77XePN-XzFJUVbC_v1-s2IcJf8uB-PMKAtRqz_kw\",\"e\":\"AQAB\"}," +
                        "{\"kty\":\"RSA\",\"n\":\"4SoqXJikILVhuwpeOYjbi_KGFXfvMaiBtoDm7nKsVc8ayQ4RBGbQdqHIt6gxSSTHrRSbQ2s5lAHfeyBJ9myQitCwxHFzjIDGcp5_u0wNWJbWUsDnbS-p" +
                        "wAQsZXZ3m6u_aDEC4sCTjOuotzwJniehVAkm2B1OnoYVhooKt9CTjVj1hwMf8Cpr171Vt559LyzUhRml6Se_AJWG_oFLV2c5ALCi2USfq2G_zoXFt9Kc93LJ9XoPy-hbQXA13" +
                        "OXwi9YL_BDLk8nd7QfaUgm77-j6RbOYg0l0PTloggw7km7M1D8iDASfkuII-Dzqedcm3KQb0Quo20HkirlIk67E-jOk6Q\",\"e\":\"AQAB\"}]}";

        JsonWebKeySet firstJkws = new JsonWebKeySet(firstJkwsJson);
        JsonWebKeySet secondJwks = new JsonWebKeySet(secondJwksJson);

        String location = "https://www.example.org/";
        HttpsJwks httpsJkws = new DefaultHttpsJwks(location);

        Get mockGet = mock(Get.class);
        Map<String,List<String>> headers = Collections.emptyMap();
        SimpleResponse ok1 = new Response(200, "OK", headers, firstJkwsJson);
        SimpleResponse ok2 = new Response(200, "OK", headers, secondJwksJson);
        when(mockGet.get(location)).thenReturn(ok1, ok2);

        httpsJkws.setRefreshReprieveThreshold(0);
        httpsJkws.setSimpleHttpGet(mockGet);

        HttpsJwksVerificationKeyResolver resolver = new HttpsJwksVerificationKeyResolver(httpsJkws);
        resolver.setDisambiguateWithVerifySignature(true);
        Key resolvedKey = resolver.resolveKey(jwsWith2ndEC, Collections.<JsonWebStructure>emptyList());
        assertThat(firstJkws.getJsonWebKeys().get(1).getKey(), equalTo(resolvedKey));

        resolvedKey = resolver.resolveKey(jwsWith1stEC, Collections.<JsonWebStructure>emptyList());
        assertThat(firstJkws.getJsonWebKeys().get(0).getKey(), equalTo(resolvedKey));

        resolvedKey = resolver.resolveKey(jwsWith3rdEC, Collections.<JsonWebStructure>emptyList()); // this one will get the second JWKS
        assertThat(secondJwks.getJsonWebKeys().get(2).getKey(), equalTo(resolvedKey));

        resolvedKey = resolver.resolveKey(jwsWith1stRsa, Collections.<JsonWebStructure>emptyList());
        assertThat(secondJwks.getJsonWebKeys().get(3).getKey(), equalTo(resolvedKey));

        resolvedKey = resolver.resolveKey(jwsWith2ndRSA, Collections.<JsonWebStructure>emptyList());
        assertThat(secondJwks.getJsonWebKeys().get(4).getKey(), equalTo(resolvedKey));

        try
        {
            resolvedKey = resolver.resolveKey(jwsWithUnknownEC, Collections.<JsonWebStructure>emptyList());
            fail("shouldn't have resolved a key but got " + resolvedKey);

        }
        catch (UnresolvableKeyException e)
        {
            log.debug("this was expected and is okay: {}", e.toString());
        }

        try
        {
            resolvedKey = resolver.resolveKey(jwsWith384EC, Collections.<JsonWebStructure>emptyList());
            fail("shouldn't have resolved a key but got " + resolvedKey);
        }
        catch (UnresolvableKeyException e)
        {
            log.debug("this was expected and is okay: {}", e.toString());
        }

    }

    @Test
    public void conformityByExtension() throws Exception
    {
        // OpenID Connect Conformance Profiles v3.0 apparently has a somewhat overzealous test to
        // Reject an ID Token without kid, if multiple JWKs are supplied in jwks_uri.
        // This test shows how to do that using a little subclass of HttpsJwksVerificationKeyResolver.
        // https://bitbucket.org/b_c/jose4j/issues/162 was asking for such a check to be put into VerificationJwkSelector
        // but that would impact and break legitimate cases (and numerous unit tests).
        // This shows a way to meet that Conformance test requirement when needed without breaking other usage.
        String jj = "{\"keys\":[" +
                        "{\"kty\":\"EC\",\"x\":\"yd4yK8EJWNY-fyB0veOTNqDt_HqpPa45VTSJjIiI8vM\",\"y\":\"UspqZi9nPaUwBY8kD6MPDHslh5f6UMnAiXsg1l3i6UM\",\"crv\":\"P-256\"}," +
                        "{\"kty\":\"EC\",\"x\":\"3WPq7AnMkQekA1ogYFqNS5NBOXPs68xadKvtsn4pgas\",\"y\":\"CEvQFmGwKv96TQYRrgS-nFl9xWfN8PuLnIwBVmtpfp0\",\"crv\":\"P-256\"}" +
                        "]}";

        JsonWebKeySet jwks = new JsonWebKeySet(jj);


        String location = "https://abc.bfe.xyz/";
        HttpsJwks httpsJkws = new DefaultHttpsJwks(location);

        Get mockGet = mock(Get.class);
        Map<String,List<String>> headers = Collections.emptyMap();
        SimpleResponse ok1 = new Response(200, "OK", headers, jj);
        when(mockGet.get(location)).thenReturn(ok1);

        httpsJkws.setRefreshReprieveThreshold(0);
        httpsJkws.setSimpleHttpGet(mockGet);


        JsonWebSignature jws = new JsonWebSignature();
        // no kid header
        jws.setCompactSerialization("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImV4cCI6MTQ5NDQzNzgwOSwiYXVkIjoidGhlIGF1ZGllbmNlIiwiaXNzIjoidGhlIGlzc3VlciJ9." +
                "uIRIFrhftV39qJNOdaL8LwrK1prIJIHsP7Gn6jJAVbE2Mx4IkwGzBXDLKMulM1IvKElmSyK_KBg8afywcxoApA");

        HttpsJwksVerificationKeyResolver resolver = new HttpsJwksVerificationKeyResolver(httpsJkws);
        resolver.setDisambiguateWithVerifySignature(true);
        jws.setKey(resolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList()));
        assertTrue(jws.verifySignature());

        CustomHttpsJwksVerificationKeyResolver customResolver = new CustomHttpsJwksVerificationKeyResolver(httpsJkws);
        try
        {
            Key key = customResolver.resolveKey(jws, Collections.<JsonWebStructure>emptyList());
            assertNull(key);
        }
        catch (UnresolvableKeyException e)
        {
            log.debug("We expected an exception out of the CustomHttpsJwksVerificationKeyResolver: " + e);
        }
    }

    public static class CustomHttpsJwksVerificationKeyResolver extends HttpsJwksVerificationKeyResolver
    {
        CustomHttpsJwksVerificationKeyResolver(HttpsJwks httpsJkws)
        {
            super(httpsJkws);
        }

        @Override
        protected JsonWebKey select(JsonWebSignature jws, List<JsonWebKey> jsonWebKeys) throws JoseException
        {
            if (jws.getKeyIdHeaderValue() == null && jsonWebKeys.size() > 1)
            {
                throw new UnresolvableKeyException("There are multiple keys in the referenced JWK Set document, but the kid value was not provided in the JOSE Header.");
            }
            return super.select(jws, jsonWebKeys);
        }
    }
}
