package com.tencent.bk.sdk.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Consumer;

/**
 * 流工具
 */
public class StreamUtils {
    public static int BUFFER_SIZE = 8192;

    /**
     * 将InputStream拷贝到OutputStream中去
     *
     * @param in  输入流
     * @param out 输出流
     */
    public static int copy(InputStream in, OutputStream out) throws IOException {
        int byteCount = 0;
        byte[] buffer = new byte[BUFFER_SIZE];
        int bytesRead;
        while ((bytesRead = in.read(buffer)) != -1) {
            out.write(buffer, 0, bytesRead);
            byteCount += bytesRead;
        }
        out.flush();
        return byteCount;
    }

    /**
     * 排出流剩余数据
     */
    public static int drain(InputStream in) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int bytesRead;
        int byteCount = 0;
        while ((bytesRead = in.read(buffer)) != -1) {
            byteCount += bytesRead;
        }
        return byteCount;
    }
}
