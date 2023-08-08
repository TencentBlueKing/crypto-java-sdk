package com.tencent.bk.sdk.util;

import com.tencent.bk.sdk.crypto.util.SM4InputStream;
import com.tencent.bk.sdk.crypto.util.SM4OutputStream;
import com.tencent.bk.sdk.crypto.util.SM4Util;
import com.tencent.bk.sdk.crypto.util.StreamUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class SM4StreamTest {
    @Test
    public void inputAndOutputTest() throws IOException {
        byte[] data = createTempData(1024);
        String key = "secretKey";

        // 明文转换成密文
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        SM4OutputStream sm4OutputStream = new SM4OutputStream(output, key);
        ByteArrayInputStream plainInputStream = new ByteArrayInputStream(data);
        StreamUtils.copy(plainInputStream, sm4OutputStream);
        byte[] encryptData = output.toByteArray();
        String encryptDataMd5 = DigestUtils.md5Hex(encryptData);
        Assertions.assertNotEquals(DigestUtils.md5Hex(data), encryptDataMd5);

        byte[] keyData = key.getBytes(StandardCharsets.UTF_8);
        byte[] decryptData = SM4Util.decrypt(keyData, encryptData);
        Assertions.assertArrayEquals(data, decryptData);

        // 密文转换成明文
        assertSuccessDecrypt(data, new ByteArrayInputStream(encryptData), key, StreamUtils.BUFFER_SIZE);
    }

    @Test
    public void bufferSizeTest() throws IOException {
        byte[] data = createTempData(10240);
        String secretKey = "secretKey";
        byte[] key = secretKey.getBytes(StandardCharsets.UTF_8);
        byte[] encryptData = SM4Util.encrypt(key, data);

        assertSuccessDecrypt(data, new ByteArrayInputStream(encryptData), secretKey, 102);
        assertSuccessDecrypt(data, new ByteArrayInputStream(encryptData), secretKey, 1024);
        assertSuccessDecrypt(data, new ByteArrayInputStream(encryptData), secretKey, 10240);
        int randomSize = new Random().nextInt(65535);
        assertSuccessDecrypt(data, new ByteArrayInputStream(encryptData), secretKey, randomSize);
    }

    @Test
    public void dataSizeTest() throws IOException {
        String secretKey = "secretKey";
        byte[] key = secretKey.getBytes(StandardCharsets.UTF_8);

        byte[] data = createTempData(1);
        assertSuccessDecrypt(data, new ByteArrayInputStream(SM4Util.encrypt(key, data)), secretKey, 1023);

        byte[] data2 = createTempData(8192);
        assertSuccessDecrypt(data2, new ByteArrayInputStream(SM4Util.encrypt(key, data2)), secretKey, 1023);

        byte[] data3 = createTempData(65535);
        assertSuccessDecrypt(data3, new ByteArrayInputStream(SM4Util.encrypt(key, data3)), secretKey, 1023);
    }

    private byte[] createTempData(int size) {
        byte[] data = new byte[size];
        new Random().nextBytes(data);
        return data;
    }

    private void assertSuccessDecrypt(byte[] except, InputStream in, String key, int size) throws IOException {
        SM4InputStream sm4InputStream = new SM4InputStream(in, key, size);
        ByteArrayOutputStream plainOutputStream = new ByteArrayOutputStream();
        StreamUtils.copy(sm4InputStream, plainOutputStream);
        Assertions.assertArrayEquals(except, plainOutputStream.toByteArray());
    }
}
