package com.tencent.bk.sdk.crypto.util;

import java.io.InputStream;

/**
 * 读取数据时，使用SM4进行解密
 */
public class SM4InputStream extends CipherInputStream {
    public SM4InputStream(InputStream in, String key, int size) {
        super(in, SM4Util.creatDecryptCipher(key, in), size);
    }

    public SM4InputStream(InputStream in, String key) {
        super(in, SM4Util.creatDecryptCipher(key, in), StreamUtils.BUFFER_SIZE);
    }
}
