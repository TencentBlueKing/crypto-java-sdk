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
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class SM4StreamTest {
    @Test
    public void inputAndOutputTest() throws IOException {
        byte[] data = new byte[1024];
        new Random().nextBytes(data);
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
        SM4InputStream sm4InputStream = new SM4InputStream(new ByteArrayInputStream(encryptData), key);
        ByteArrayOutputStream plainOutputStream = new ByteArrayOutputStream();
        StreamUtils.copy(sm4InputStream, plainOutputStream);
        Assertions.assertArrayEquals(data, plainOutputStream.toByteArray());
    }
}
