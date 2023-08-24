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

package com.tencent.bk.sdk.util;

import com.tencent.bk.sdk.crypto.cryptor.CryptorMetaDefinition;
import com.tencent.bk.sdk.crypto.util.CryptorMetaUtil;
import org.junit.jupiter.api.Test;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class CryptorMetaUtilTest {
    @Test
    public void testGetCryptorNameFromCipher() {
        // 密文元数据前后缀验证
        assertEquals(CryptorMetaDefinition.getCipherMetaPrefix(), CryptorMetaUtil.getCipherMetaPrefix());
        assertEquals(CryptorMetaDefinition.getCipherMetaSuffix(), CryptorMetaUtil.getCipherMetaSuffix());
        // 异常用例
        assertNull(CryptorMetaUtil.getCryptorNameFromCipher(null));
        assertNull(CryptorMetaUtil.getCryptorNameFromCipher(""));
        assertNull(CryptorMetaUtil.getCryptorNameFromCipher("AAA"));
        assertNull(CryptorMetaUtil.getCryptorNameFromCipher("[Cipher:]"));
        assertNull(CryptorMetaUtil.getCryptorNameFromCipher("[Cipher::AAA]"));
        // 正常用例
        assertEquals("", CryptorMetaUtil.getCryptorNameFromCipher("[Cipher:::]"));
        assertEquals("AES", CryptorMetaUtil.getCryptorNameFromCipher("[Cipher:::AES]"));
        assertEquals("AES_CBC", CryptorMetaUtil.getCryptorNameFromCipher("[Cipher:::AES_CBC]"));
        assertEquals("SM4", CryptorMetaUtil.getCryptorNameFromCipher("[Cipher:::SM4]"));
    }

    @Test
    public void testGetCryptorNameFromCipherStream() throws IOException {
        // 异常用例
        String cipherStr = "aaabbbcccdddeeefff";
        InputStream ins = new ByteArrayInputStream(cipherStr.getBytes(StandardCharsets.UTF_8));
        BufferedInputStream bis = new BufferedInputStream(ins);
        String cryptorName = CryptorMetaUtil.getCryptorNameFromCipherStream(bis);
        BufferedReader reader = new BufferedReader(new InputStreamReader(bis));
        assertNull(cryptorName);
        assertEquals(cipherStr, reader.readLine());
        reader.close();
        // 正常用例
        cipherStr = "[Cipher:::SM4]aaabbbcccdddeeefff";
        ins = new ByteArrayInputStream(cipherStr.getBytes(StandardCharsets.UTF_8));
        bis = new BufferedInputStream(ins);
        cryptorName = CryptorMetaUtil.getCryptorNameFromCipherStream(bis);
        reader = new BufferedReader(new InputStreamReader(bis));
        assertEquals("SM4", cryptorName);
        assertEquals(cipherStr, reader.readLine());
        reader.close();
    }
}
