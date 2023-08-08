package com.tencent.bk.sdk.crypto.util;

import com.tencent.kona.crypto.KonaCryptoProvider;

import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * 国密散列算法SM3相关操作工具类
 */
public class SM3Util {

    /**
     * 散列算法
     */
    private static final String ALGORITHM_SM3 = "SM3";

    static {
        KonaCryptoProvider konaCryptoProvider = new KonaCryptoProvider();
        if (null == Security.getProvider(konaCryptoProvider.getName())) {
            Security.addProvider(konaCryptoProvider);
        }
    }

    /**
     * 对消息进行摘要
     *
     * @param message 消息
     * @return 摘要
     */
    public static byte[] digest(byte[] message) {
        try {
            MessageDigest md = MessageDigest.getInstance(ALGORITHM_SM3);
            return md.digest(message);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Digest error.", e);
        }
    }

    /**
     * 对流进行摘要
     *
     * @param in 输入流
     * @return 摘要
     */
    public static byte[] digest(InputStream in) {
        try {
            MessageDigest md = MessageDigest.getInstance(ALGORITHM_SM3);
            DigestInputStream digestInputStream = new DigestInputStream(in, md);
            StreamUtils.drain(digestInputStream);
            return digestInputStream.getMessageDigest().digest();
        } catch (Exception e) {
            throw new IllegalStateException("Digest error.", e);
        }
    }
}
