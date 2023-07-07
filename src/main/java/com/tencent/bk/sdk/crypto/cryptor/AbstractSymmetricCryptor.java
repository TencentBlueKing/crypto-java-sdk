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

package com.tencent.bk.sdk.crypto.cryptor;

import com.tencent.bk.sdk.crypto.exception.CryptoException;
import com.tencent.bk.sdk.crypto.util.Base64Util;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import java.nio.charset.StandardCharsets;

public abstract class AbstractSymmetricCryptor implements SymmetricCryptor {

    public abstract byte[] encryptIndeed(@NonNull byte[] key, @NonNull byte[] message);

    public abstract byte[] decryptIndeed(@NonNull byte[] key, @NonNull byte[] encryptedMessage);

    public byte[] encrypt(byte[] key, byte[] message) {
        if (key == null || key.length == 0) {
            throw new CryptoException("encrypt key is invalid: null or empty");
        }
        if (message == null || message.length == 0) {
            return message;
        }
        return encryptIndeed(key, message);
    }

    public byte[] decrypt(byte[] key, byte[] encryptedMessage) {
        if (key == null || key.length == 0) {
            throw new CryptoException("decrypt key is invalid: null or empty");
        }
        if (encryptedMessage == null || encryptedMessage.length == 0) {
            return encryptedMessage;
        }
        return decryptIndeed(key, encryptedMessage);
    }

    public abstract String getName();

    public String getStringCipherPrefix() {
        return "[Cipher:::" + getName() + "]";
    }

    @Override
    public String encrypt(String key, String message) throws CryptoException {
        if (StringUtils.isEmpty(key)) {
            throw new CryptoException("encrypt key is invalid: null or empty");
        }
        if (StringUtils.isEmpty(message)) {
            return message;
        }
        byte[] encryptedMessage = encrypt(
            key.getBytes(StandardCharsets.UTF_8),
            message.getBytes(StandardCharsets.UTF_8)
        );
        String finalCipher = Base64Util.encodeContentToStr(encryptedMessage);
        String prefix = getStringCipherPrefix();
        if (prefix != null) {
            finalCipher = prefix + finalCipher;
        }
        return finalCipher;
    }

    @Override
    public String decrypt(String key, String base64MessageWithPrefix) {
        if (StringUtils.isEmpty(key)) {
            throw new CryptoException("decrypt key is invalid: null or empty");
        }
        if (StringUtils.isEmpty(base64MessageWithPrefix)) {
            return base64MessageWithPrefix;
        }
        String base64EncryptedMessage = StringUtils.removeStart(base64MessageWithPrefix, getStringCipherPrefix());
        byte[] rawEncryptedMessage = Base64Util.decodeContentToByte(base64EncryptedMessage);
        byte[] decryptedMessage = decrypt(
            key.getBytes(StandardCharsets.UTF_8),
            rawEncryptedMessage
        );
        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }
}
