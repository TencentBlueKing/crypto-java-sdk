/*
 * Tencent is pleased to support the open source community by making 蓝鲸加解密Java SDK（crypto-java-sdk） available.
 *
 * Copyright (C) 2021 THL A29 Limited, a Tencent company.  All rights reserved.
 *
 * 蓝鲸加解密Java SDK（crypto-java-sdk） is licensed under the MIT License.
 *
 * License for 蓝鲸加解密Java SDK（crypto-java-sdk）:
 * --------------------------------------------------------------------
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
 * to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 * THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

package com.tencent.bk.sdk.crypto.util;

import com.tencent.bk.sdk.crypto.exception.CryptoException;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 非对称加密算法RSA相关操作工具类
 */
public class RSAUtil {
    private static final String KEY_ALGORITHM = "RSA";
    private static final int DEFAULT_KEY_SIZE = 2048;

    public static KeyPair genKeyPair() {
        return genKeyPair(DEFAULT_KEY_SIZE);
    }

    public static KeyPair genKeyPair(int keySize) {
        KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Fail to gen RSA key pair", e);
        }
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    public static byte[] encryptToBytes(PublicKey publicKey, byte[] messageBytes) {
        if (messageBytes == null || messageBytes.length == 0) {
            throw new CryptoException("messageBytes is invalid: null or empty");
        }
        try {
            Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(messageBytes);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Fail to encrypt message using RSA", e);
        }
    }

    public static byte[] decryptToBytes(PrivateKey privateKey, byte[] cipherBytes) {
        if (cipherBytes == null || cipherBytes.length == 0) {
            throw new CryptoException("cipherBytes is invalid: null or empty");
        }
        try {
            Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(cipherBytes);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Fail to decrypt cipher using RSA", e);
        }
    }
}
