/*
 * Copyright 2012-2013 Brian Campbell
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

package org.jose4j.jwe;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwx.Headers;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.HmacKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.mac.MacUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 */
public class AesCbcHmacSha2ContentEncryptionAlgorithm extends AlgorithmInfo implements ContentEncryptionAlgorithm
{
    private final String hmacJavaAlgorithm;
    private final int tagTruncationLength;
    private final ContentEncryptionKeyDescriptor contentEncryptionKeyDescriptor;

    public AesCbcHmacSha2ContentEncryptionAlgorithm(String alg, int cekByteLen, String javaHmacAlg, int tagTruncationLength)
    {
        setAlgorithmIdentifier(alg);
        contentEncryptionKeyDescriptor = new ContentEncryptionKeyDescriptor(cekByteLen, AesKey.ALGORITHM);
        this.hmacJavaAlgorithm = javaHmacAlg;
        this.tagTruncationLength = tagTruncationLength;
        setJavaAlgorithm("AES/CBC/PKCS5Padding");
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        setKeyType(AesKey.ALGORITHM);
    }

    public String getHmacJavaAlgorithm()
    {
        return hmacJavaAlgorithm;
    }

    public int getTagTruncationLength()
    {
        return tagTruncationLength;
    }

    public ContentEncryptionKeyDescriptor getContentEncryptionKeyDescriptor()
    {
        return contentEncryptionKeyDescriptor;
    }

    public ContentEncryptionParts encrypt(byte[] plaintext, byte[] aad, byte[] contentEncryptionKey, Headers headers) throws JoseException
    {
        // The Initialization Vector (IV) used is a 128 bit value generated
        //       randomly or pseudorandomly for use in the cipher.
        byte[] iv = ByteUtil.randomBytes(16);
        return encrypt(plaintext, aad, contentEncryptionKey, iv);
    }

    ContentEncryptionParts encrypt(byte[] plaintext, byte[] aad, byte[] key, byte[] iv) throws JoseException
    {
        Key hmacKey = new HmacKey(ByteUtil.leftHalf(key));
        Key encryptionKey = new AesKey(ByteUtil.rightHalf(key));

        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm());

        try
        {
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Invalid key for " + getJavaAlgorithm(), e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException(e.toString(), e);
        }

        byte[] cipherText;
        try
        {
            cipherText = cipher.doFinal(plaintext);
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }

        Mac mac = MacUtil.getInitializedMac(getHmacJavaAlgorithm(), hmacKey);

        byte[] al = getAdditionalAuthenticatedDataLengthBytes(aad);

        byte[] authenticationTagInput = ByteUtil.concat(aad, iv, cipherText, al);
        byte[] authenticationTag = mac.doFinal(authenticationTagInput);
        authenticationTag = ByteUtil.subArray(authenticationTag, 0, getTagTruncationLength()); // truncate it

        return new ContentEncryptionParts(iv, cipherText, authenticationTag);
    }


    public byte[] decrypt(ContentEncryptionParts contentEncryptionParts, byte[] aad, byte[] contentEncryptionKey, Headers headers) throws JoseException
    {
        byte[] iv = contentEncryptionParts.getIv();
        byte[] ciphertext = contentEncryptionParts.getCiphertext();
        byte[] authenticationTag = contentEncryptionParts.getAuthenticationTag();
        byte[] al = getAdditionalAuthenticatedDataLengthBytes(aad);
        byte[] authenticationTagInput = ByteUtil.concat(aad, iv, ciphertext, al);
        Key hmacKey = new HmacKey(ByteUtil.leftHalf(contentEncryptionKey));
        Mac mac = MacUtil.getInitializedMac(getHmacJavaAlgorithm(), hmacKey);
        byte[] calculatedAuthenticationTag = mac.doFinal(authenticationTagInput);
        calculatedAuthenticationTag = ByteUtil.subArray(calculatedAuthenticationTag, 0, getTagTruncationLength()); // truncate it
        boolean tagMatch = ByteUtil.secureEquals(authenticationTag, calculatedAuthenticationTag);
        if (!tagMatch)
        {
            Base64Url base64Url = new Base64Url();
            String encTag = base64Url.base64UrlEncode(authenticationTag);
            String calcEncTag = base64Url.base64UrlEncode(calculatedAuthenticationTag);
            throw new JoseException("Authentication tag failed. Message=" + encTag + " calculated=" + calcEncTag);
        }

        Key encryptionKey = new AesKey(ByteUtil.rightHalf(contentEncryptionKey));

        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm());
        try
        {
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Invalid key for " + getJavaAlgorithm(), e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException(e.toString(), e);
        }

        try
        {
            return cipher.doFinal(ciphertext);
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }
    }

    private byte[] getAdditionalAuthenticatedDataLengthBytes(byte[] additionalAuthenticatedData)
    {
        // The octet string AL is equal to the number of bits in associated data A expressed
        //       as a 64-bit unsigned integer in network byte order.
        long aadLength = ByteUtil.bitLength(additionalAuthenticatedData);
        return ByteUtil.getBytes(aadLength);
    }

    @Override
    public boolean isAvailable()
    {
        int contentEncryptionKeyByteLength = getContentEncryptionKeyDescriptor().getContentEncryptionKeyByteLength();
        int aesByteKeyLength = contentEncryptionKeyByteLength / 2;
        return CipherStrengthSupport.isAvailable(getJavaAlgorithm(), aesByteKeyLength);
    }
}