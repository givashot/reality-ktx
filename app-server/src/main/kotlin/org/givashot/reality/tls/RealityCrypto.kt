package org.givashot.reality.tls

import org.givashot.tls.ClientHelloWrapper
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

    fun decryptSessionId(
        authKey: ByteArray,
        clientHelloWrapper: ClientHelloWrapper,
    ): ByteArray {
        require(authKey.size == 32 && clientHelloWrapper.base.sessionID.size == 32)
        val nonce = clientHelloWrapper.base.random.copyOfRange(20, 32)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(authKey, "AES"),
            GCMParameterSpec(128, nonce),
        )
        cipher.updateAAD(clientHelloWrapper.aadWithZeroedSessionId())
        val plaintext = cipher.doFinal(clientHelloWrapper.base.sessionID)
        require(plaintext.size == 16) { "Plaintext must be 16 bytes" }
        return plaintext
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
