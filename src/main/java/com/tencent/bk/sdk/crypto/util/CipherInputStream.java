package com.tencent.bk.sdk.crypto.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * 读取Cipher处理过的数据，将其转换成明文。
 */
public class CipherInputStream extends FilterInputStream {
    /**
     * 密码器
     */
    protected Cipher cipher;

    /**
     * 读取缓冲区
     */
    protected byte[] buf;

    /**
     * 明文数据
     */
    protected byte[] plainData;

    /**
     * 明文数据读取位置
     */
    protected int plainDataPos = 0;

    // this flag is set to true after EOF has reached
    private boolean reachEOF = false;


    private boolean closed = false;

    private void ensureOpen() throws IOException {
        if (closed) {
            throw new IOException("Stream closed");
        }
    }

    /**
     * 创建一个使用了指定密码器和缓冲区大小的流
     *
     * @param in     输入流
     * @param cipher 密码器
     * @param size   输入流缓冲区大小
     */
    public CipherInputStream(InputStream in, Cipher cipher, int size) {
        super(in);
        buf = new byte[size];
        this.cipher = cipher;
    }

    /**
     * 单字节缓冲区
     */
    private byte[] singleByteBuf = new byte[1];

    @Override
    public int read() throws IOException {
        return read(singleByteBuf, 0, 1) == -1 ? -1 : Byte.toUnsignedInt(singleByteBuf[0]);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        ensureOpen();
        if (b == null) {
            throw new NullPointerException();
        } else if (off < 0 || len < 0 || len > b.length - off) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return 0;
        }
        if (readableSize() == 0 && fill() == -1) {
            return -1;
        }
        if (readableSize() < len) {
            int read = 0;
            do {
                int rz = readableSize();
                System.arraycopy(plainData, plainDataPos, b, off, rz);
                plainDataPos += rz;
                off += rz;
                read += rz;
                if (readableSize() <= 0 && fill() == -1) {
                    return read;
                }
            } while (read < len);
        } else {
            System.arraycopy(plainData, plainDataPos, b, off, len);
            plainDataPos += len;
        }
        return len;
    }

    /**
     * 当前可读数据大小
     */
    private int readableSize() {
        if (plainData == null) {
            return 0;
        }
        return plainData.length - plainDataPos;
    }

    /**
     * 填充数据
     * 解密更多的数据，填充到明文数据
     */
    private int fill() throws IOException {
        int read = in.read(buf);
        int updated = -1;
        if (read == -1) {
            try {
                plainData = cipher.doFinal();
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new IllegalStateException(e);
            }
        } else {
            plainData = cipher.update(buf, 0, read);
        }
        if (plainData != null && plainData.length > 0) {
            updated = plainData.length;
        }
        plainDataPos = 0;
        return updated;
    }

    @Override
    public int available() throws IOException {
        ensureOpen();
        if (reachEOF) {
            return 0;
        } else {
            return 1;
        }
    }

    private byte[] b = new byte[512];

    @Override
    public long skip(long n) throws IOException {
        if (n < 0) {
            throw new IllegalArgumentException("negative skip length");
        }
        int max = (int) Math.min(n, Integer.MAX_VALUE);
        int total = 0;
        while (total < max) {
            int len = max - total;
            if (len > b.length) {
                len = b.length;
            }
            len = read(b, 0, len);
            if (len == -1) {
                reachEOF = true;
                break;
            }
            total += len;
        }
        return total;
    }

    @Override
    public void close() throws IOException {
        if (!closed) {
            in.close();
            closed = true;
        }
    }

    @Override
    public boolean markSupported() {
        return false;
    }

    @Override
    public synchronized void mark(int readlimit) {
        // do nothing
    }

    @Override
    public synchronized void reset() throws IOException {
        throw new IOException("mark/reset not supported");
    }
}
