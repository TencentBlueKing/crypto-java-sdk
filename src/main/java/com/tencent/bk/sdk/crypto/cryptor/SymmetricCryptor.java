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

/**
 * 对称加密器接口
 */
public interface SymmetricCryptor {
    /**
     * 加密
     *
     * @param key     密钥字节数组
     * @param message 要加密的明文字节数组
     * @return 加密后的密文字节数组
     */
    byte[] encrypt(byte[] key, byte[] message);

    /**
     * 解密
     *
     * @param key              密钥字节数组
     * @param encryptedMessage 加密后的密文字节数组
     * @return 解密后的明文字节数组
     */
    byte[] decrypt(byte[] key, byte[] encryptedMessage);

    /**
     * 加密
     *
     * @param key     密钥字符串
     * @param message 要加密的明文字符串（UTF-8编码）
     * @return 加密后的密文字节数组，经过base64编码得到的字符串
     */
    String encrypt(String key, String message);

    /**
     * 解密
     *
     * @param key                           密钥字符串
     * @param base64EncodedEncryptedMessage base64编码的【加密后的密文字节数组】
     * @return 解密后的明文字符串（UTF-8编码）
     */
    String decrypt(String key, String base64EncodedEncryptedMessage);
}
