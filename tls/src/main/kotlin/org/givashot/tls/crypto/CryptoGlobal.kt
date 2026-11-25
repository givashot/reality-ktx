package org.givashot.tls.crypto

import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap
import javax.crypto.Cipher
import javax.crypto.Mac

private val cipherMap: ConcurrentMap<String, ThreadLocal<Cipher>> by lazy {
    ConcurrentHashMap()
}

fun tlsCipher(transformation: String): Cipher {
    return (cipherMap[transformation] ?: cipherMap.computeIfAbsent(transformation) {
        ThreadLocal.withInitial { Cipher.getInstance(transformation) }
    }).get()
}

private val macMap: ConcurrentMap<String, ThreadLocal<Mac>> by lazy {
    ConcurrentHashMap()
}

fun tlsMac(transformation: String): Mac {
    return (macMap[transformation] ?: macMap.computeIfAbsent(transformation) {
        ThreadLocal.withInitial { Mac.getInstance(transformation) }
    }).get()
}

private val mdMap: ConcurrentMap<String, ThreadLocal<MessageDigest>> by lazy {
    ConcurrentHashMap()
}

fun tlsMd(algorithm: String): MessageDigest {
    return (mdMap[algorithm] ?: mdMap.computeIfAbsent(algorithm) {
        ThreadLocal.withInitial { MessageDigest.getInstance(algorithm) }
    }).get()
}