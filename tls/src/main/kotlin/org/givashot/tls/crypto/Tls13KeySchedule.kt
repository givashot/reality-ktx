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

    /**
     * 基于HandshakeSecret + TranscriptHash 算出 HandshakeTrafficSecrets
     * 当前TranscriptHash = Hash(CH + SH)
     * HandshakeSecret基于shared secret计算出来的（无 PSK 场景）
     * 也就是HandshakeTrafficSecrets是基于shared secret + TranscriptHash得来
     * HandshakeTrafficSecrets用于TLS HANDSHAKE MESSAGE加解密
     * FINISHED（双端）的PAYLOAD消息体会基于HandshakeTrafficSecrets计算得来
     * 双端在准备发送HANDSHAKE TYPE的TLS RECORD时，会使用HandshakeTrafficSecrets来加密TLS RECORD，
     * 最终TLS RECORD的CONTENT TYPE为APPLICATION DATA，HANDSHAKE TYPE会保留在解密TLS RECORD的PAYLOAD中的最后一个非0字节
     */
    fun handshakeTrafficSecrets(transcriptHash: ByteArray): HandshakeTrafficSecrets {
        val clientTraffic = clientHandshakeTrafficSecret(transcriptHash)
        val serverTraffic = serverHandshakeTrafficSecret(transcriptHash)
        return HandshakeTrafficSecrets(
            serverHandshakeTrafficSecret = serverTraffic,
            clientHandshakeTrafficSecret = clientTraffic,
            serverWriteKey = expandKey(serverTraffic),
            serverWriteIv = expandIv(serverTraffic),
            clientWriteKey = expandKey(clientTraffic),
            clientWriteIv = expandIv(clientTraffic),
            cipherSuite = cipherSuite,
        )
    }

    /**
     * 基于MasterSecret + TranscriptHash 算出 ApplicationTrafficSecrets
     * 当前TranscriptHash = Hash(CH + SH + EE + CA + CAV + FINISH)
     * MasterSecret基于HandshakeSecret计算出来
     * ApplicationTrafficSecrets用于TLS APPLICATION MESSAGE加解密
     * 双端在发送ApplicationData TYPE的TLS RECORD时，会使用ApplicationTrafficSecrets来加密TLS RECORD
     */
    fun applicationTrafficSecrets(transcriptHash: ByteArray): ApplicationTrafficSecrets {
        require(transcriptHash.size == cipherSuite.hashLength)
        val clientTraffic = clientApplicationTrafficSecret(transcriptHash)
        val serverTraffic = serverApplicationTrafficSecret(transcriptHash)
        return ApplicationTrafficSecrets(
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

    /**
     * 客户端发送过来的FINISHED是通过ClientHandshakeTrafficSecret + transcriptHash(CH + 客户端接收到的（SH + EE + CA + CAV + FINISH）)计算得来
     * 我们模拟客户端算法，通过ClientHandshakeTrafficSecret + transcriptHash(CH + 服务端本地记录的（SH + EE + CA + CAV + FINISH）)计算出EXPECT CLIENT FINISHED
     * 再比较这两个数据，如果客户端接收到的（SH + EE + CA + CAV + FINISH）和 服务端本地记录的（SH + EE + CA + CAV + FINISH）不一致
     * 或者ClientHandshakeTrafficSecret算出来的和我们算出来的不一致
     * 都会导致校验失败。
     */
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
