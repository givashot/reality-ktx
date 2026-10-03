package org.givashot.tls.crypto

import org.givashot.tls.constant.TLS_HANDSHAKE_FINISH_CONTENT_TYPE
import java.security.MessageDigest

internal fun finishedVerifyData(
    trafficSecret: ByteArray,
    transcriptHash: ByteArray,
    cipherSuite: CipherSuite,
): ByteArray = hmac(
    hkdfExpandLabel(trafficSecret, "finished", ByteArray(0), cipherSuite.hashLength, cipherSuite),
    transcriptHash,
    cipherSuite,
)

/** TLS 1.3 HKDF key schedule (RFC 8446 section 7.1). Stages must be derived in order. */
internal class Tls13KeySchedule(private val cipherSuite: CipherSuite) {
    private var earlySecret: ByteArray? = null
    private var handshakeSecret: ByteArray? = null
    private var masterSecret: ByteArray? = null

    fun deriveEarlySecret(psk: ByteArray? = null) {
        val zero = ByteArray(cipherSuite.hashLength)
        earlySecret = hkdfExtract(zero, psk ?: zero, cipherSuite)
    }

    fun deriveHandshakeSecret(sharedSecret: ByteArray) {
        require(sharedSecret.size == 32) { "X25519 shared secret must be 32 bytes" }
        val early = checkNotNull(earlySecret) { "Early secret has not been derived" }
        handshakeSecret = hkdfExtract(deriveSecret(early), sharedSecret, cipherSuite)
    }

    fun deriveMasterSecret() {
        val handshake = checkNotNull(handshakeSecret) { "Handshake secret has not been derived" }
        masterSecret = hkdfExtract(deriveSecret(handshake), ByteArray(cipherSuite.hashLength), cipherSuite)
    }

    fun clientHandshakeTrafficSecret(transcriptHash: ByteArray): ByteArray =
        trafficSecret(handshakeSecret, "c hs traffic", transcriptHash)

    fun serverHandshakeTrafficSecret(transcriptHash: ByteArray): ByteArray =
        trafficSecret(handshakeSecret, "s hs traffic", transcriptHash)

    fun clientApplicationTrafficSecret(transcriptHash: ByteArray): ByteArray =
        trafficSecret(masterSecret, "c ap traffic", transcriptHash)

    fun serverApplicationTrafficSecret(transcriptHash: ByteArray): ByteArray =
        trafficSecret(masterSecret, "s ap traffic", transcriptHash)

    fun handshakeSecrets(transcriptHash: ByteArray): HandshakeSecrets {
        val clientTraffic = clientHandshakeTrafficSecret(transcriptHash)
        val serverTraffic = serverHandshakeTrafficSecret(transcriptHash)
        return HandshakeSecrets(
            serverHandshakeTrafficSecret = serverTraffic,
            clientHandshakeTrafficSecret = clientTraffic,
            serverWriteKey = expandKey(serverTraffic),
            serverWriteIv = expandIv(serverTraffic),
            clientWriteKey = expandKey(clientTraffic),
            clientWriteIv = expandIv(clientTraffic),
            cipherSuite = cipherSuite,
        )
    }

    fun applicationSecrets(transcriptHash: ByteArray): ApplicationSecrets {
        require(transcriptHash.size == cipherSuite.hashLength)
        val clientTraffic = clientApplicationTrafficSecret(transcriptHash)
        val serverTraffic = serverApplicationTrafficSecret(transcriptHash)
        return ApplicationSecrets(
            clientAppTrafficSecret = clientTraffic,
            serverAppTrafficSecret = serverTraffic,
            serverWriteKey = expandKey(serverTraffic),
            serverWriteIv = expandIv(serverTraffic),
            clientWriteKey = expandKey(clientTraffic),
            clientWriteIv = expandIv(clientTraffic),
            cipherSuite = cipherSuite,
        )
    }

    fun finishedVerifyData(trafficSecret: ByteArray, transcriptHash: ByteArray): ByteArray =
        finishedVerifyData(trafficSecret, transcriptHash, cipherSuite)

    fun verifyClientFinished(
        message: ByteArray,
        clientHandshakeTrafficSecret: ByteArray,
        transcriptHash: ByteArray,
    ): Boolean = runCatching {
        require(message.size >= 4 && (message[0].toInt() and 0xFF) == TLS_HANDSHAKE_FINISH_CONTENT_TYPE)
        val length = ((message[1].toInt() and 0xFF) shl 16) or
            ((message[2].toInt() and 0xFF) shl 8) or
            (message[3].toInt() and 0xFF)
        require(length == message.size - 4)
        require(length == cipherSuite.hashLength)
        val expected = finishedVerifyData(clientHandshakeTrafficSecret, transcriptHash)
        MessageDigest.isEqual(expected, message.copyOfRange(4, message.size))
    }.getOrDefault(false)

    private fun deriveSecret(secret: ByteArray): ByteArray =
        hkdfExpandLabel(secret, "derived", emptyHash(cipherSuite), cipherSuite.hashLength, cipherSuite)

    private fun trafficSecret(secret: ByteArray?, label: String, transcriptHash: ByteArray): ByteArray {
        val base = checkNotNull(secret) { "Secret for \"$label\" has not been derived" }
        return hkdfExpandLabel(base, label, transcriptHash, cipherSuite.hashLength, cipherSuite)
    }

    private fun expandKey(trafficSecret: ByteArray): ByteArray =
        hkdfExpandLabel(trafficSecret, "key", ByteArray(0), cipherSuite.keyLen, cipherSuite)

    private fun expandIv(trafficSecret: ByteArray): ByteArray =
        hkdfExpandLabel(trafficSecret, "iv", ByteArray(0), cipherSuite.ivLen, cipherSuite)
}
