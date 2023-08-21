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

import com.tencent.bk.sdk.crypto.cryptor.CryptorMetaDefinition;
import com.tencent.bk.sdk.crypto.exception.CryptoException;
import com.tencent.kona.crypto.CryptoUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 加密器元数据操作工具类
 */
@Slf4j
public class CryptorMetaUtil {

    /**
     * 获取密文元数据前缀
     *
     * @return 密文元数据前缀
     */
    public static String getCipherMetaPrefix() {
        return CryptorMetaDefinition.getCipherMetaPrefix();
    }

    /**
     * 获取密文元数据后缀
     *
     * @return 密文元数据后缀
     */
    public static String getCipherMetaSuffix() {
        return CryptorMetaDefinition.getCipherMetaSuffix();
    }

    /**
     * 为密文字节数组添加前缀
     *
     * @param prefix         前缀
     * @param encryptedBytes 加密后的密文字节数组
     * @return 带前缀的密文字节数组
     */
    public static byte[] addPrefixToEncryptedBytes(String prefix, byte[] encryptedBytes) {
        if (StringUtils.isEmpty(prefix)) {
            return encryptedBytes;
        }
        byte[] prefixBytes = prefix.getBytes(StandardCharsets.UTF_8);
        byte[] finalBytes = new byte[encryptedBytes.length + prefixBytes.length];
        System.arraycopy(prefixBytes, 0, finalBytes, 0, prefixBytes.length);
        System.arraycopy(encryptedBytes, 0, finalBytes, prefixBytes.length, encryptedBytes.length);
        return finalBytes;
    }

    /**
     * 移除密文字节数组中的前缀
     *
     * @param prefix         前缀
     * @param encryptedBytes 带前缀的密文字节数组
     * @return 移除了前缀的密文字节数组
     */
    public static byte[] removePrefixFromEncryptedBytes(String prefix, byte[] encryptedBytes) {
        byte[] expectedPrefixBytes = prefix.getBytes(StandardCharsets.UTF_8);
        byte[] prefixBytes = new byte[expectedPrefixBytes.length];
        System.arraycopy(encryptedBytes, 0, prefixBytes, 0, prefixBytes.length);
        if (!Arrays.equals(prefixBytes, expectedPrefixBytes)) {
            throw new CryptoException(
                "encryptedMessage is invalid: prefix bytes unexpected, whose hex should be: " +
                    CryptoUtils.toHex(expectedPrefixBytes)
            );
        }
        byte[] pureEncryptedBytes = new byte[encryptedBytes.length - prefixBytes.length];
        System.arraycopy(encryptedBytes, prefixBytes.length, pureEncryptedBytes, 0, pureEncryptedBytes.length);
        return pureEncryptedBytes;
    }

    /**
     * 从密文的前缀元数据中解析出使用的加密器名称
     *
     * @param cipher 密文
     * @return 加密器名称，如果密文不包含指定前缀的元数据则返回null
     */
    public static String getCryptorNameFromCipher(String cipher) {
        String prefix = getCipherMetaPrefix();
        if (cipher.startsWith(prefix)) {
            int indexOfPrefixLastChar = cipher.indexOf(getCipherMetaSuffix());
            if (indexOfPrefixLastChar < 0) {
                return null;
            }
            return cipher.substring(prefix.length(), indexOfPrefixLastChar);
        }
        return null;
    }

    /**
     * 从密文的前缀元数据中解析出使用的加密器名称
     *
     * @param cipherIns 密文输入流
     * @return 加密器名称，如果密文不包含指定前缀的元数据则返回null
     */
    public static String getCryptorNameFromCipherStream(BufferedInputStream cipherIns) {
        String prefix = getCipherMetaPrefix();
        String suffix = getCipherMetaSuffix();
        int cryptorNameMaxLength = 100;
        int cipherMetaMaxLength = prefix.length() + suffix.length() + cryptorNameMaxLength;
        cipherIns.mark(cipherMetaMaxLength);
        byte[] realPrefixBytes = new byte[prefix.length()];
        try {
            int n = cipherIns.read(realPrefixBytes);
            if (n < prefix.length()) {
                log.info("Cannot find enough cipherMetaPrefix bytes: expected={}, actually={}", prefix.length(), n);
                return null;
            }
            if (!Arrays.equals(realPrefixBytes, prefix.getBytes())) {
                log.info(
                    "Cannot find cipherMetaPrefix: expected={}, actually={}",
                    Arrays.toString(prefix.getBytes()),
                    Arrays.toString(realPrefixBytes)
                );
                return null;
            }
            byte[] cryptorNameWithSuffixBytes = new byte[cryptorNameMaxLength + suffix.length()];
            n = cipherIns.read(cryptorNameWithSuffixBytes);
            String cryptorNameWithSuffix = new String(cryptorNameWithSuffixBytes);
            int indexOfSuffix = cryptorNameWithSuffix.indexOf(suffix);
            if (indexOfSuffix == -1) {
                log.info(
                    "Cannot find cipherMetaSuffix: cryptorNameWithSuffixBytes={}, suffixBytes={}",
                    Arrays.toString(cryptorNameWithSuffixBytes),
                    suffix.getBytes()
                );
                return null;
            }
            return cryptorNameWithSuffix.substring(0, indexOfSuffix);
        } catch (Exception e) {
            log.warn("Fail to read cipherMetaPrefix from cipherIns", e);
            return null;
        } finally {
            try {
                cipherIns.reset();
            } catch (IOException e) {
                log.error("Fail to reset cipherIns", e);
            }
        }
    }

}
