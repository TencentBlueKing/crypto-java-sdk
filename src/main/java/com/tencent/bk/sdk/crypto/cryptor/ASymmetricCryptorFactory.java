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
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 非对称加密器工厂
 */
@Slf4j
public class ASymmetricCryptorFactory {

    static Map<String, ASymmetricCryptor> aSymmetricCryptorMap = new ConcurrentHashMap<>();
    static AtomicBoolean load = new AtomicBoolean(false);

    public static ASymmetricCryptor getCryptor(String name) {
        if (!load.get()) {
            init();
        }
        ASymmetricCryptor cryptor = aSymmetricCryptorMap.get(name);
        if (cryptor != null) {
            return cryptor;
        }
        throw new CryptorNotFoundException("ASymmetricCryptor for " + name + " not found");
    }

    private static void init() {

        if (!load.compareAndSet(false, true)) {
            return;
        }

        ServiceLoader<ASymmetricCryptor> serviceLoader = ServiceLoader.load(ASymmetricCryptor.class);

        if (!serviceLoader.iterator().hasNext()) {
            serviceLoader = ServiceLoader.load(ASymmetricCryptor.class, ServiceLoader.class.getClassLoader());
        }
        Map<String, Integer> candidatePriorityMap = new HashMap<>();
        Map<String, ASymmetricCryptor> candidateMap = new HashMap<>();

        for (ASymmetricCryptor aSymmetricCryptor : serviceLoader) {
            // 默认值
            String cryptorName = aSymmetricCryptor.getClass().getCanonicalName();
            int priority = 0;
            // 从注解解析
            Cryptor cryptoAnonation = aSymmetricCryptor.getClass().getAnnotation(Cryptor.class);
            if (cryptoAnonation != null) {
                if (cryptoAnonation.type() != CryptorTypeEnum.ASYMMETRIC) {
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
                candidateMap.put(cryptorName, aSymmetricCryptor);
            }
        }
        candidateMap.forEach((cryptorName, cryptor) -> {
            aSymmetricCryptorMap.put(cryptorName, cryptor);
            log.info("Add ASymmetricCryptor " + cryptorName
                + " Crypto(" + candidatePriorityMap.get(cryptorName) + ") for " + cryptor);
        });
    }
}
