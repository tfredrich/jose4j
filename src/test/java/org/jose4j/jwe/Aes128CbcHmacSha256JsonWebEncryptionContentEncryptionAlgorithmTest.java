package org.jose4j.jwe;

import junit.framework.TestCase;
import org.jose4j.base64url.Base64Url;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;

/**
 */
public class Aes128CbcHmacSha256JsonWebEncryptionContentEncryptionAlgorithmTest extends TestCase
{
    public void testExampleEncryptFromJweAppendix2() throws JoseException
    {
        // http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-13#appendix-A.2
        String plainTextText = "Live long and prosper.";
        byte[] plainText = StringUtil.getBytesUtf8(plainTextText);

        String encodedHeader = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
        byte[] aad = StringUtil.getBytesAscii(encodedHeader);

        int[] ints = {4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207};
        byte[] contentEncryptionKeyBytes = ByteUtil.convertUnsignedToSignedTwosComp(ints);

        byte[] iv = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101});

        Aes128CbcHmacSha256JsonWebEncryptionContentEncryptionAlgorithm jweContentEncryptionAlg = new Aes128CbcHmacSha256JsonWebEncryptionContentEncryptionAlgorithm();
        JsonWebEncryptionContentEncryptionAlgorithm.EncryptionResult encryptionResult = jweContentEncryptionAlg.encrypt(plainText, aad, contentEncryptionKeyBytes, iv);

        Base64Url base64Url = new Base64Url();

        byte[] ciphertext = encryptionResult.getCiphertext();
        String encodedJweCiphertext = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY";
        assertEquals(base64Url.base64UrlEncode(ciphertext), encodedJweCiphertext);
    }

}
