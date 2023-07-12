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
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * 对称加密算法AES相关操作工具类
 */
public class AESUtil extends BasicCipherUtil {
    /**
     * 加密/解密算法/工作模式/填充方式
     */
    private static final String CIPHER_ALGORITHM = "AES/CTR/NoPadding";

    /**
     * 加密数据
     *
     * @param data 待加密数据
     * @param key  密钥
     * @return byte[] 加密后的数据
     */
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        if (data == null || data.length == 0) {
            return data;
        }
        if (key == null || key.length == 0) {
            throw new CryptoException("encrypt key is invalid: null or empty");
        }
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, getKeySpec(cipher, key));

        byte[] iv = cipher.getIV();
        byte[] finalData = cipher.doFinal(data);
        if (iv == null) {
            throw new RuntimeException(String.format("CIPHER_ALGORITHM %s is invalid", CIPHER_ALGORITHM));
        }
        byte[] finalDataWithIv = new byte[finalData.length + iv.length];
        System.arraycopy(iv, 0, finalDataWithIv, 0, iv.length);
        System.arraycopy(finalData, 0, finalDataWithIv, iv.length, finalData.length);
        return finalDataWithIv;
    }

    /**
     * 对输入流中的数据加密，并写入到输出流中
     * 注意：该方法不对输入流与输出流做关闭操作，需要外层调用方自行处理
     *
     * @param key 密钥
     * @param in  输入流
     * @param out 输出流
     */
    public static void encrypt(String key, InputStream in, OutputStream out) throws Exception {
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, getKeySpec(cipher, keyBytes));
        byte[] arr = cipher.getIV();
        if (arr == null) {
            throw new RuntimeException(String.format("CIPHER_ALGORITHM %s is invalid", CIPHER_ALGORITHM));
        }
        out.write(arr);
        write(in, out, cipher);
    }

    /**
     * 解密数据
     *
     * @param data 待解密数据
     * @param key  密钥
     * @return byte[] 解密后的数据
     */
    public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
        if (data == null || data.length == 0) {
            return data;
        }
        if (key == null || key.length == 0) {
            throw new CryptoException("decrypt key is invalid: null or empty");
        }
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, getKeySpec(cipher, key), getIvSpec(cipher, data));
        byte[] dataWithoutIv = new byte[data.length - cipher.getBlockSize()];
        System.arraycopy(data, cipher.getBlockSize(), dataWithoutIv,
            0, data.length - cipher.getBlockSize());
        return cipher.doFinal(dataWithoutIv);
    }

    /**
     * 对输入流中的数据解密，并写入到输出流中
     * 注意：该方法不对输入流与输出流做关闭操作，需要外层调用方自行处理
     *
     * @param key 密钥
     * @param in  输入流
     * @param out 输出流
     */
    public static void decrypt(String key, InputStream in, OutputStream out) throws Exception {
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        byte[] iv = new byte[cipher.getBlockSize()];
        if (in.read(iv) < iv.length) {
            throw new RuntimeException();
        }
        cipher.init(Cipher.DECRYPT_MODE, getKeySpec(cipher, keyBytes), new IvParameterSpec(iv));
        write(in, out, cipher);
    }

    private static IvParameterSpec getIvSpec(Cipher cipher, byte[] data) {
        byte[] iv = new byte[cipher.getBlockSize()];
        System.arraycopy(data, 0, iv, 0, iv.length);
        return new IvParameterSpec(iv);
    }

    private static SecretKeySpec getKeySpec(Cipher cipher, byte[] key)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed(key);
        kgen.init(cipher.getBlockSize() * 8, random);
        return new SecretKeySpec(kgen.generateKey().getEncoded(), "AES");
    }
}
