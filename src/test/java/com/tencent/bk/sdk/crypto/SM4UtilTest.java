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

/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package com.tencent.bk.sdk.crypto;

import com.tencent.bk.sdk.crypto.util.SM4Util;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static com.tencent.kona.crypto.CryptoUtils.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SM4UtilTest {

    private static final byte[] EMPTY_KEY = "".getBytes(StandardCharsets.UTF_8);
    private static final byte[] EMPTY_MESSAGE = "".getBytes(StandardCharsets.UTF_8);

    private static final String KEY = "中文符号~!@#$%^&*();test";
    private static final byte[] KEY_BYTES = KEY.getBytes(StandardCharsets.UTF_8);
    private static final String MESSAGE = "test中文符号~!@#$%^&*()_+=-0987654321`[]{};:'\"<>?,./";
    private static final byte[] MESSAGE_BYTES = MESSAGE.getBytes(StandardCharsets.UTF_8);

    @Test
    void testEncrypt() {
        // 空值用例
        // key与message同时为空
        byte[] emptyCipheredMessage = SM4Util.encrypt(EMPTY_KEY, EMPTY_MESSAGE);
        System.out.println(toHex(emptyCipheredMessage));
        byte[] emptyMessageByEmptyKey = SM4Util.decrypt(EMPTY_KEY, emptyCipheredMessage);
        assertArrayEquals(emptyMessageByEmptyKey, EMPTY_MESSAGE);

        // key为空，message不为空
        byte[] emptyKeyCipheredMessage = SM4Util.encrypt(EMPTY_KEY, MESSAGE_BYTES);
        System.out.println(toHex(emptyKeyCipheredMessage));
        byte[] messageByEmptyKey = SM4Util.decrypt(EMPTY_KEY, emptyKeyCipheredMessage);
        assertArrayEquals(messageByEmptyKey, MESSAGE_BYTES);

        // key不为空，message为空
        byte[] emptyMessageCipheredMessage = SM4Util.encrypt(KEY_BYTES, EMPTY_MESSAGE);
        System.out.println(toHex(emptyMessageCipheredMessage));
        byte[] emptyMessageByNormalKey = SM4Util.decrypt(KEY_BYTES, emptyMessageCipheredMessage);
        assertArrayEquals(emptyMessageByNormalKey, EMPTY_MESSAGE);

        // 一般用例
        byte[] realCipheredMessage = SM4Util.encrypt(KEY_BYTES, MESSAGE_BYTES);
        System.out.println(toHex(realCipheredMessage));
        byte[] normalMessage = SM4Util.decrypt(KEY_BYTES, realCipheredMessage);
        assertArrayEquals(normalMessage, MESSAGE_BYTES);
    }

    @Test
    void testEncryptAndDecryptStream() throws Exception {
        // 加密
        InputStream in = SM4UtilTest.class.getClassLoader().getResourceAsStream("fileToEncrypt.txt");
        String outFilePath = new File("").getAbsolutePath() + "/out/encryptedFile.encrypt.sm4";
        FileOutputStream out = new FileOutputStream(outFilePath);
        SM4Util.encrypt(KEY, in, out);
        if (in != null) {
            in.close();
        }
        out.close();
        // 解密
        String inFilePath = new File("").getAbsolutePath() + "/out/encryptedFile.encrypt.sm4";
        in = new FileInputStream(inFilePath);
        String decryptedFilePath = new File("").getAbsolutePath() + "/out/decryptedFile.txt.sm4";
        out = new FileOutputStream(decryptedFilePath);
        SM4Util.decrypt(KEY, in, out);
        in.close();
        out.close();
        // 验证
        in = SM4UtilTest.class.getClassLoader().getResourceAsStream("fileToEncrypt.txt");
        assert in != null;
        String srcFileMd5 = DigestUtils.md5Hex(in);
        FileInputStream fis = new FileInputStream(decryptedFilePath);
        String decryptedFileMd5 = DigestUtils.md5Hex(fis);
        assertEquals(srcFileMd5, decryptedFileMd5);
        in.close();
        fis.close();
    }

}
