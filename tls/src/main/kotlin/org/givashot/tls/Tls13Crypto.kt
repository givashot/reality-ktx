package org.givashot.tls

import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val TLS_INNER_TYPE_HANDSHAKE = 22
private const val TLS_INNER_TYPE_APPLICATION_DATA = 23
private const val TLS_RECORD_VERSION_HIGH = 3
private const val TLS_RECORD_VERSION_LOW = 3
private const val TLS_AEAD_TAG_LENGTH = 16

internal data class DecryptedTlsRecord(
    val contentType: Int,
    val payload: ByteArray,
)

internal fun digest(data: ByteArray, cipherSuite: CipherSuite): ByteArray =
    MessageDigest.getInstance(cipherSuite.hash).digest(data)

fun tlsTranscriptHash(cipherSuite: CipherSuite, vararg messages: ByteArray): ByteArray =
    digest(messages.fold(ByteArray(0)) { result, message -> result + message }, cipherSuite)

internal fun hkdfExtract(salt: ByteArray, input: ByteArray, cipherSuite: CipherSuite): ByteArray =
    hmac(salt, input, cipherSuite)

internal fun hkdfExpand(
    pseudoRandomKey: ByteArray,
    info: ByteArray,
    length: Int,
    cipherSuite: CipherSuite,
): ByteArray {
    require(length in 0..255 * cipherSuite.hashLength)
    if (length == 0) return ByteArray(0)

    val output = ByteArray(length)
    var previous = ByteArray(0)
    var offset = 0
    var counter = 1
    while (offset < length) {
        previous = hmac(pseudoRandomKey, previous + info + counter.toByte(), cipherSuite)
        val copied = minOf(previous.size, length - offset)
        previous.copyInto(output, offset, 0, copied)
        offset += copied
        counter++
    }
    return output
}

internal fun hkdfExpandLabel(
    secret: ByteArray,
    label: String,
    context: ByteArray,
    length: Int,
    cipherSuite: CipherSuite,
): ByteArray {
    val fullLabel = "tls13 $label".toByteArray(Charsets.US_ASCII)
    require(fullLabel.size <= 255 && context.size <= 255)
    val info = ByteBuffer.allocate(2 + 1 + fullLabel.size + 1 + context.size)
        .putShort(length.toShort())
        .put(fullLabel.size.toByte())
        .put(fullLabel)
        .put(context.size.toByte())
        .put(context)
        .array()
    return hkdfExpand(secret, info, length, cipherSuite)
}

internal fun emptyHash(cipherSuite: CipherSuite): ByteArray = digest(ByteArray(0), cipherSuite)

internal fun hmac(key: ByteArray, input: ByteArray, cipherSuite: CipherSuite): ByteArray =
    Mac.getInstance("Hmac${cipherSuite.hash.replace("-", "")}").run {
        init(SecretKeySpec(key, algorithm))
        doFinal(input)
    }

internal fun tlsHandshakeMessage(type: Int, body: ByteArray): ByteArray {
    require(type in 0..255 && body.size <= 0xFFFFFF)
    return byteArrayOf(
        type.toByte(),
        (body.size ushr 16).toByte(),
        (body.size ushr 8).toByte(),
        body.size.toByte(),
    ) + body
}

internal fun tlsRecord(contentType: Int, payload: ByteArray): ByteArray {
    require(contentType in 0..255 && payload.size <= 0xFFFF)
    return byteArrayOf(
        contentType.toByte(),
        TLS_RECORD_VERSION_HIGH.toByte(),
        TLS_RECORD_VERSION_LOW.toByte(),
        (payload.size ushr 8).toByte(),
        payload.size.toByte(),
    ) + payload
}

internal fun encryptTlsRecord(
    contentType: Int,
    plaintext: ByteArray,
    writeKey: ByteArray,
    writeIv: ByteArray,
    sequenceNumber: Long,
    cipherSuite: CipherSuite,
    paddingLength: Int = 0,
): ByteArray {
    require(sequenceNumber >= 0)
    require(paddingLength >= 0)
    val inner = plaintext + ByteArray(paddingLength) + contentType.toByte()
    val ciphertextLength = inner.size + TLS_AEAD_TAG_LENGTH
    require(ciphertextLength <= 0xFFFF) { "TLS ciphertext record is too large" }
    val header = byteArrayOf(
        TLS_INNER_TYPE_APPLICATION_DATA.toByte(),
        TLS_RECORD_VERSION_HIGH.toByte(),
        TLS_RECORD_VERSION_LOW.toByte(),
        (ciphertextLength ushr 8).toByte(),
        ciphertextLength.toByte(),
    )
    val nonce = writeIv.copyOf().also { value ->
        for (index in 0 until Long.SIZE_BYTES) {
            value[value.size - 1 - index] =
                (value[value.size - 1 - index].toInt() xor (sequenceNumber ushr (index * 8)).toInt()).toByte()
        }
    }
    val cipher = createAeadCipher(Cipher.ENCRYPT_MODE, writeKey, nonce, cipherSuite)
    cipher.updateAAD(header)
    return header + cipher.doFinal(inner)
}

internal fun decryptTlsRecord(
    record: ByteArray,
    writeKey: ByteArray,
    writeIv: ByteArray,
    sequenceNumber: Long,
    cipherSuite: CipherSuite,
): DecryptedTlsRecord {
    require(record.size >= 5 + TLS_AEAD_TAG_LENGTH + 1)
    require(record[0].toInt() and 0xFF == TLS_INNER_TYPE_APPLICATION_DATA)
    require(record[1].toInt() and 0xFF == TLS_RECORD_VERSION_HIGH)
    require(record[2].toInt() and 0xFF == TLS_RECORD_VERSION_LOW)
    val length = ((record[3].toInt() and 0xFF) shl 8) or (record[4].toInt() and 0xFF)
    require(length == record.size - 5)

    val header = record.copyOfRange(0, 5)
    val ciphertext = record.copyOfRange(5, record.size)
    val nonce = writeIv.copyOf().also { value ->
        for (index in 0 until Long.SIZE_BYTES) {
            value[value.size - 1 - index] =
                (value[value.size - 1 - index].toInt() xor (sequenceNumber ushr (index * 8)).toInt()).toByte()
        }
    }
    val cipher = createAeadCipher(Cipher.DECRYPT_MODE, writeKey, nonce, cipherSuite)
    cipher.updateAAD(header)
    val inner = cipher.doFinal(ciphertext)
    var contentEnd = inner.size - 1
    while (contentEnd >= 0 && inner[contentEnd].toInt() == 0) contentEnd--
    require(contentEnd >= 0)
    val contentType = inner[contentEnd].toInt() and 0xFF
    require(contentType == TLS_INNER_TYPE_HANDSHAKE || contentType == TLS_INNER_TYPE_APPLICATION_DATA)
    return DecryptedTlsRecord(contentType, inner.copyOfRange(0, contentEnd))
}

private fun createAeadCipher(
    mode: Int,
    key: ByteArray,
    nonce: ByteArray,
    cipherSuite: CipherSuite,
): Cipher {
    val cipher = Cipher.getInstance(cipherSuite.aead)
    val keySpec = SecretKeySpec(key, if (cipherSuite.aead.startsWith("AES")) "AES" else "ChaCha20")
    if (cipherSuite.aead.startsWith("AES")) {
        cipher.init(mode, keySpec, GCMParameterSpec(cipherSuite.tagLen * 8, nonce))
    } else {
        cipher.init(mode, keySpec, IvParameterSpec(nonce))
    }
    return cipher
}