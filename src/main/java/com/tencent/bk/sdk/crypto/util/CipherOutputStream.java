package com.tencent.bk.sdk.crypto.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * 使用Cipher对数据进行加密后写入。
 */
public class CipherOutputStream extends FilterOutputStream {
    protected Cipher cipher;
    private boolean writedIv = false;
    private byte[] iv;

    private boolean closed = false;

    public CipherOutputStream(OutputStream out, Cipher cipher) {
        super(out);
        this.cipher = cipher;
        this.iv = cipher.getIV();
    }

    @Override
    public void write(int b) throws IOException {
        byte[] buf = new byte[1];
        buf[0] = (byte) (b & 0xff);
        write(buf, 0, 1);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (iv != null && !writedIv) {
            out.write(iv);
            writedIv = true;
        }
        byte[] encryptData = cipher.update(b, off, len);
        if (encryptData != null && encryptData.length > 0) {
            out.write(encryptData, 0, encryptData.length);
        }
    }

    @Override
    public void flush() throws IOException {
        try {
            byte[] encryptData = cipher.doFinal();
            if (encryptData != null && encryptData.length > 0) {
                out.write(encryptData);
            }
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalStateException(e);
        }
        out.flush();
    }

    @Override
    public void close() throws IOException {
        if (!closed) {
            out.close();
            closed = true;
        }
    }
}
