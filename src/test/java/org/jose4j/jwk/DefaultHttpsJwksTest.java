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

import org.jose4j.http.Get;
import org.jose4j.http.Response;
import org.jose4j.http.SimpleResponse;
import org.jose4j.keys.X509Util;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class DefaultHttpsJwksTest
{
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Test
    public void testExpiresDateHeadersPerRfc() throws Exception
    {
        /*
              3 different HTTP date formats per
              http://tools.ietf.org/html/rfc7231#section-7.1.1.1  or
              http://tools.ietf.org/html/rfc2616#section-3.3.1
              Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123
              Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036
              Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format
         */
        long actualDateMs = 784111777000L;
        long actualCacheLife = 60L;
        long fakeCurrentTime = 784111717000L;

        Map<String, List<String>> headers = Collections.singletonMap("Expires", Collections.singletonList("Sun, 06 Nov 1994 08:49:37 GMT"));
        SimpleResponse simpleResponse = new Response(200, "OK", headers, "doesn't matter");
        assertThat(actualDateMs, equalTo(HttpsJwks.getExpires(simpleResponse)));
        assertThat(actualCacheLife, equalTo(DefaultHttpsJwks.getCacheLife(simpleResponse, fakeCurrentTime)));

        headers = Collections.singletonMap("Expires", Collections.singletonList("Sunday, 06-Nov-94 08:49:37 GMT"));
        simpleResponse = new Response(200, "OK", headers, "doesn't matter");
        assertThat(actualDateMs, equalTo(HttpsJwks.getExpires(simpleResponse)));
        assertThat(actualCacheLife, equalTo(DefaultHttpsJwks.getCacheLife(simpleResponse, fakeCurrentTime)));

        headers = Collections.singletonMap("Expires", Collections.singletonList("Sun Nov  6 08:49:37 1994"));
        simpleResponse = new Response(200, "OK", headers, "*still* doesn't matter");
        assertThat(actualDateMs, equalTo(HttpsJwks.getExpires(simpleResponse)));
        assertThat(actualCacheLife, equalTo(DefaultHttpsJwks.getCacheLife(simpleResponse, fakeCurrentTime)));
    }

    @Test
    public void testCacheLifeFromCacheControlMaxAge() throws Exception
    {
        String[] headerValues =
        {
            "public, max-age=23760, must-revalidate, no-transform",
            "public, max-age=    23760 , must-revalidate",
            "public,max-age = 23760, must-revalidate",
            "public, max-age=23760, must-revalidate, no-transform",
            "must-revalidate,public,max-age=23760,no-transform",
            "max-age =23760, must-revalidate, public",
            "max-age=23760",
            "max-age =23760",
            "max-age = 23760 ",
            "max-age=23760,",
            "fake=\"f,a,k,e\",public, max-age=23760, must-revalidate=\"this , shouldn't be here\", whatever",
        };

        for (String headerValue : headerValues)
        {
            Map<String, List<String>> headers = new HashMap<>();
            headers.put("Expires", Collections.singletonList("Expires: Tue, 27 Jan 2015 16:00:10 GMT")); // Cache-Control takes precedence over this
            headers.put("Cache-Control", Collections.singletonList(headerValue));
            SimpleResponse simpleResponse = new Response(200, "OK", headers, "doesn't matter");
            long cacheLife = DefaultHttpsJwks.getCacheLife(simpleResponse);
            assertThat("it done broke on this one " + headerValue, 23760L , equalTo(cacheLife));
        }
    }

    // todo more tests

    @Test
    @Ignore // skip this one b/c of external dependency and manual intervention needed
    public void testKindaSimplisticConcurrent() throws Exception
    {
        X509Util x509Util = new X509Util();
        X509Certificate certificate = x509Util.fromBase64Der(
                "MIICUDCCAbkCBETczdcwDQYJKoZIhvcNAQEFBQAwbzELMAkGA1UEBhMCVVMxCzAJ\n" +
                "BgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxFTATBgNVBAoTDFBpbmdJZGVudGl0\n" +
                "eTEXMBUGA1UECxMOQnJpYW4gQ2FtcGJlbGwxEjAQBgNVBAMTCWxvY2FsaG9zdDAe\n" +
                "Fw0wNjA4MTExODM1MDNaFw0zMzEyMjcxODM1MDNaMG8xCzAJBgNVBAYTAlVTMQsw\n" +
                "CQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRUwEwYDVQQKEwxQaW5nSWRlbnRp\n" +
                "dHkxFzAVBgNVBAsTDkJyaWFuIENhbXBiZWxsMRIwEAYDVQQDEwlsb2NhbGhvc3Qw\n" +
                "gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJLrpeiY/Ai2gGFxNY8Tm/QSO8qg\n" +
                "POGKDMAT08QMyHRlxW8fpezfBTAtKcEsztPzwYTLWmf6opfJT+5N6cJKacxWchn/\n" +
                "dRrzV2BoNuz1uo7wlpRqwcaOoi6yHuopNuNO1ms1vmlv3POq5qzMe6c1LRGADyZh\n" +
                "i0KejDX6+jVaDiUTAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAMojbPEYJiIWgQzZc\n" +
                "QJCQeodtKSJl5+lA8MWBBFFyZmvZ6jUYglIQdLlc8Pu6JF2j/hZEeTI87z/DOT6U\n" +
                "uqZA83gZcy6re4wMnZvY2kWX9CsVWDCaZhnyhjBNYfhcOf0ZychoKShaEpTQ5UAG\n" +
                "wvYYcbqIWC04GAZYVsZxlPl9hoA=\n");

        X509Certificate x509Certificate = x509Util.fromBase64Der(
                "MIIDVjCCAj6gAwIBAgIGAV+2AcB2MA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNVBAYT\n" +
                "AlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRUwEwYDVQQKEwxQaW5n\n" +
                "SWRlbnRpdHkxFDASBgNVBAsTC0RldmVsb3BtZW50MRIwEAYDVQQDEwlsb2NhbGhv\n" +
                "c3QwHhcNMTcxMTEzMTUzMTI5WhcNMjcxMTE0MTUzMTI5WjBsMQswCQYDVQQGEwJV\n" +
                "UzELMAkGA1UECBMCQ08xDzANBgNVBAcTBkRlbnZlcjEVMBMGA1UEChMMUGluZ0lk\n" +
                "ZW50aXR5MRQwEgYDVQQLEwtEZXZlbG9wbWVudDESMBAGA1UEAxMJbG9jYWxob3N0\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjAjwydAR/F3pNntK9YCa\n" +
                "5ewJ6qrW8BUbZsB7G3FvK2lD2jezp47PswQ6M2QbNAlkA7zv8qOcBb2lleoCyc70\n" +
                "127MvkD3Pfrw5BSXR1LH8QhxIeayRVK0T28qmfMU9fc9zyn0rpB4eeC5KYSe9pXW\n" +
                "vg+MUpE2hnW0ZaTkXWQxriBU46DEuiJ8qhd2ACoxHo1NQEWBTJt2fWVWe9Ai/YuE\n" +
                "72g7DQdxZTamwo74Gp4RBZuVS+4xh42e0chktkNKNRo5/8Nkhb8CWNgjwakiNPXL\n" +
                "4bIzyh0+/KQoUoyRz61Oj5Q6FXbIlEJhDFFZGuHgiMi1JR0CvQEoYng80d3Lj/Dw\n" +
                "XwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAZcFMBOONUTdm9xZZ5Cnwlti+rzmE4\n" +
                "w0JRAEazFXLdMim1PWwlaJ7dvqqLXJklLV/4uSocvoMFNAjpoR1v27mj7aWe0WD9\n" +
                "NU/z+yiEvSjSzCoWWUbBYLxgOz+ZaP78SOU+SFzuZYaBj7GiZbj4MkDaozReDMmM\n" +
                "uGJsSJeKo3qQVja6ma71gDyupTg9pu8h+Dk7NUB8AOEIX8bncheKKtiC/IiPa/PO\n" +
                "nik9VuDu1Oq/W7d6bRzw3GrBq5puPX9ATonRqRqmWu4AMRi0G5kA75rWXes9TOII\n" +
                "BK3F71z66Z6qlxIYDZl5qYIJEIE71/YqWIEzR4Cqpu59c3oJ7obdyGTz");

        long start = System.currentTimeMillis();

        String location = "https://localhost:9031/pf/JWKS";
//        location = "https://login.salesforce.com/id/keys";
//        location = "https://www.googleapis.com/oauth2/v3/certs";
//        location = "https://login.microsoftonline.com/consumers/discovery/v2.0/keys";

        Get get = new Get();
        get.setTrustedCertificates(certificate, x509Certificate);

        final HttpsJwks httpsJwks = new DefaultHttpsJwks(location);
        httpsJwks.setSimpleHttpGet(get);
        httpsJwks.setDefaultCacheDuration(1);
        httpsJwks.setRetainCacheOnErrorDuration(1);

        Callable<List> task = new Callable<List>()
        {
            @Override
            public List<JsonWebKey> call() throws Exception
            {
                List<JsonWebKey> jsonWebKeys = null;
                for (long i = 200000000 ; i > 0 ; i--)
                {
                    jsonWebKeys = httpsJwks.getJsonWebKeys();
                    assertFalse(jsonWebKeys.isEmpty());
                    if (i % 11000000 == 0) { httpsJwks.refresh(); }
                    if (i % 10000000 == 0) { log.debug("... working ... " + i + " ... " + Thread.currentThread().toString());}
                }
                return jsonWebKeys;
            }
        };

        int threadCount = 15;
        ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        List<Callable<List>> tasks = Collections.nCopies(threadCount, task);

        List<Future<List>> futures = executorService.invokeAll(tasks);
        log.debug("=== and done ===");

        for (Future<List> future : futures)
        {
            log.debug(future.get().toString());
        }

        System.out.println(System.currentTimeMillis() - start);
    }
}
