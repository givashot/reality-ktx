package org.givashot.appclient.tls

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object RealityCrypto {
    private val label = "REALITY".toByteArray(Charsets.US_ASCII)

    fun calculateAuthKey(sharedSecret: ByteArray, clientHelloRandom: ByteArray): ByteArray {
        require(clientHelloRandom.size == 32) { "ClientHello random must be 32 bytes" }
        return hkdfSha256(sharedSecret, clientHelloRandom.copyOfRange(0, 20), label, 32)
    }

    fun encryptSessionId(
        authKey: ByteArray,
        clientHelloRandom: ByteArray,
        shortId: ByteArray,
        clientHelloRaw: ByteArray,
        sessionIdOffset: Int
    ): ByteArray {
        // 1. 准备 16 字节明文
        val plaintext = ByteArray(16)
        plaintext[0] = 2
        plaintext[1] = 3
        plaintext[2] = 4
        // reserved
        plaintext[3] = 0
        // 写入 4 字节大端时间戳
        val timestamp = (System.currentTimeMillis() / 1000).toInt()
        plaintext[4] = (timestamp shr 24).toByte()
        plaintext[5] = (timestamp shr 16).toByte()
        plaintext[6] = (timestamp shr 8).toByte()
        plaintext[7] = timestamp.toByte()
        // 写入 8 字节 shortId
        require(shortId.size == 8) { "ShortId must be 8 bytes" }
        shortId.copyInto(plaintext, 8)

        // 2. 准备 nonce = Random 的后 12 字节
        val nonce = clientHelloRandom.copyOfRange(20, 32)

        // 3. 准备 AAD（非常重要！）
        // 把 ClientHello 原始数据中 session_id 的位置全部置为 0
        val aad = clientHelloRaw.copyOf()
        aad.fill(0, sessionIdOffset, sessionIdOffset + 32)

        // 4. 加密得到最终的 32 字节 legacy_session_id
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(authKey, "AES")
        val gcmSpec = GCMParameterSpec(128, nonce)   // 128-bit tag = 16 字节

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        // 设置 AAD（Additional Authenticated Data）
        cipher.updateAAD(aad)

        // 执行加密，返回 16字节密文 + 16字节Tag = 32字节
        return cipher.doFinal(plaintext)
    }

    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32) { "HKDF output length is out of range" }
        val prk = hmacSha256(salt, ikm)
        val output = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            previous = hmacSha256(prk, previous + info + counter.toByte())
            val copied = minOf(previous.size, length - offset)
            previous.copyInto(output, offset, 0, copied)
            offset += copied
            counter++
        }
        return output
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, algorithm))
            doFinal(data)
        }
}

class ByteArrayKey(val bytes: ByteArray) {
    override fun equals(other: Any?): Boolean = other is ByteArrayKey && bytes.contentEquals(other.bytes)
    override fun hashCode(): Int = bytes.contentHashCode()
}