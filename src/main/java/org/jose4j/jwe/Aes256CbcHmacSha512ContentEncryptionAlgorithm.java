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

import org.jose4j.mac.MacUtil;

/**
 */
public class Aes256CbcHmacSha512ContentEncryptionAlgorithm
        extends AesCbcHmacSha2ContentEncryptionAlgorithm
        implements ContentEncryptionAlgorithm
{
    public Aes256CbcHmacSha512ContentEncryptionAlgorithm()
    {
        // ENC_KEY_LEN is 32 octets & MAC_KEY_LEN is 32 octets.
        // The HMAC SHA-512 value is truncated to T_LEN=32 octets instead of 16 octets.
        super(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512, 64, MacUtil.HMAC_SHA512, 32);
    }
}