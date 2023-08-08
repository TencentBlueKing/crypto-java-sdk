package com.tencent.bk.sdk.crypto;

import com.tencent.bk.sdk.crypto.util.SM3Util;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.Random;

public class SM3UtilTest {
    @Test
    public void digestBytesTest() {
        byte[] bytes = new byte[1024];
        new Random().nextBytes(bytes);
        byte[] digestBytes = SM3Util.digest(bytes);
        String digest = Hex.encodeHexString(digestBytes);
        System.out.println(digest);
    }

    @Test
    public void digestInputStreamTest() {
        byte[] bytes = new byte[1024];
        new Random().nextBytes(bytes);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
        byte[] digestBytes = SM3Util.digest(inputStream);
        String digest = Hex.encodeHexString(digestBytes);
        System.out.println(digest);
    }
}
