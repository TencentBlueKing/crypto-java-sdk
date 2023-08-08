package com.tencent.bk.sdk.crypto.util;

import java.io.OutputStream;

import static com.tencent.bk.sdk.crypto.util.SM4Util.creatEncryptCipher;

/**
 * 数据写入时，使用SM4进行加密
 */
public class SM4OutputStream extends CipherOutputStream {

    public SM4OutputStream(OutputStream out, String key) {
        super(out, creatEncryptCipher(key));
    }
}
