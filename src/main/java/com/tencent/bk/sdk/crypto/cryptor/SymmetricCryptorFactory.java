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

package com.tencent.bk.sdk.crypto.cryptor;

import com.tencent.bk.sdk.crypto.annotation.Cryptor;
import com.tencent.bk.sdk.crypto.annotation.CryptorTypeEnum;
import com.tencent.bk.sdk.crypto.exception.CryptorNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 对称加密器工厂
 */
@Slf4j
public class SymmetricCryptorFactory {

    static Map<String, SymmetricCryptor> symmetricCryptorMap = new ConcurrentHashMap<>();
    static AtomicBoolean loading = new AtomicBoolean(false);
    static CountDownLatch latch = new CountDownLatch(1);

    public static SymmetricCryptor getCryptor(String name) {
        if (!loading.get()) {
            init();
        }
        if (latch.getCount() > 0) {
            try {
                latch.await();
            } catch (InterruptedException e) {
                log.error("wait for SymmetricCryptorFactory load interrupted", e);
            }
        }
        SymmetricCryptor cryptor = symmetricCryptorMap.get(name);
        if (cryptor != null) {
            return cryptor;
        }
        throw new CryptorNotFoundException("SymmetricCryptor for " + name + " not found");
    }

    private static void init() {
        if (!loading.compareAndSet(false, true)) {
            return;
        }
        try {
            findCryptors();
        } catch (Exception e) {
            log.error("Exception occurred when findCryptors", e);
        } finally {
            latch.countDown();
        }
    }

    private static void findCryptors() {
        ServiceLoader<SymmetricCryptor> serviceLoader = ServiceLoader.load(SymmetricCryptor.class);

        if (!serviceLoader.iterator().hasNext()) {
            serviceLoader = ServiceLoader.load(SymmetricCryptor.class, ServiceLoader.class.getClassLoader());
        }
        Map<String, Integer> candidatePriorityMap = new HashMap<>();
        Map<String, SymmetricCryptor> candidateMap = new HashMap<>();

        for (SymmetricCryptor symmetricCryptor : serviceLoader) {
            // 默认值
            String cryptorName = symmetricCryptor.getClass().getCanonicalName();
            int priority = 0;
            // 从注解解析
            Cryptor cryptoAnonation = symmetricCryptor.getClass().getAnnotation(Cryptor.class);
            if (cryptoAnonation != null) {
                if (cryptoAnonation.type() != CryptorTypeEnum.SYMMETRIC) {
                    continue;
                }
                if (StringUtils.isNotBlank(cryptoAnonation.name())) {
                    cryptorName = cryptoAnonation.name();
                }
                priority = cryptoAnonation.priority();
            }
            // 覆盖低优先级实现
            Integer oldPriority = candidatePriorityMap.get(cryptorName);
            if (oldPriority == null || priority > oldPriority) {
                candidatePriorityMap.put(cryptorName, priority);
                candidateMap.put(cryptorName, symmetricCryptor);
            }
        }
        candidateMap.forEach((cryptorName, cryptor) -> {
            symmetricCryptorMap.put(cryptorName, cryptor);
            log.info("Add SymmetricCryptor " + cryptorName
                + " Crypto(" + candidatePriorityMap.get(cryptorName) + ") for " + cryptor);
        });
    }
}
