package org.givashot.tls.crypto

import org.givashot.tls.constant.TLS_HANDSHAKE_FINISH_CONTENT_TYPE
import org.givashot.tls.handshake.CipherSuite
import java.security.MessageDigest

internal object KeySchedule {
    fun deriveHandshakeSecrets(
        sharedSecret: ByteArray,
        transcriptHash: ByteArray,
        cipherSuite: CipherSuite,
    ): HandshakeSecrets {
        require(sharedSecret.size == 32) { "X25519 shared secret must be 32 bytes" }

        val zero = ByteArray(cipherSuite.hashLength)
        val earlySecret = hkdfExtract(zero, zero, cipherSuite)
        val derivedEarlySecret = hkdfExpandLabel(
            earlySecret,
            "derived",
            emptyHash(cipherSuite),
            cipherSuite.hashLength,
            cipherSuite,
        )
        val handshakeSecret = hkdfExtract(derivedEarlySecret, sharedSecret, cipherSuite)
        val clientTraffic = hkdfExpandLabel(
            handshakeSecret,
            "c hs traffic",
            transcriptHash,
            cipherSuite.hashLength,
            cipherSuite,
        )
        val serverTraffic = hkdfExpandLabel(
            handshakeSecret,
            "s hs traffic",
            transcriptHash,
            cipherSuite.hashLength,
            cipherSuite,
        )
        val derivedHandshakeSecret = hkdfExpandLabel(
            handshakeSecret,
            "derived",
            emptyHash(cipherSuite),
            cipherSuite.hashLength,
            cipherSuite,
        )
        val masterSecret = hkdfExtract(derivedHandshakeSecret, zero, cipherSuite)

        return HandshakeSecrets(
            handshakeSecret = handshakeSecret,
            serverHandshakeTrafficSecret = serverTraffic,
            clientHandshakeTrafficSecret = clientTraffic,
            serverWriteKey = hkdfExpandLabel(serverTraffic, "key", ByteArray(0), cipherSuite.keyLen, cipherSuite),
            serverWriteIv = hkdfExpandLabel(serverTraffic, "iv", ByteArray(0), cipherSuite.ivLen, cipherSuite),
            clientWriteKey = hkdfExpandLabel(clientTraffic, "key", ByteArray(0), cipherSuite.keyLen, cipherSuite),
            clientWriteIv = hkdfExpandLabel(clientTraffic, "iv", ByteArray(0), cipherSuite.ivLen, cipherSuite),
            transcriptHash = transcriptHash,
            cipherSuite = cipherSuite,
            masterSecret = masterSecret,
        )
    }

    fun deriveApplicationSecrets(
        handshake: HandshakeSecrets,
        transcriptHash: ByteArray,
    ): ApplicationSecrets {
        require(transcriptHash.size == handshake.cipherSuite.hashLength)
        val suite = handshake.cipherSuite
        val clientApplicationSecret = hkdfExpandLabel(
            handshake.masterSecret,
            "c ap traffic",
            transcriptHash,
            suite.hashLength,
            suite,
        )
        val serverApplicationSecret = hkdfExpandLabel(
            handshake.masterSecret,
            "s ap traffic",
            transcriptHash,
            suite.hashLength,
            suite,
        )
        return ApplicationSecrets(
            clientAppTrafficSecret = clientApplicationSecret,
            serverAppTrafficSecret = serverApplicationSecret,
            serverWriteKey = hkdfExpandLabel(serverApplicationSecret, "key", ByteArray(0), suite.keyLen, suite),
            serverWriteIv = hkdfExpandLabel(serverApplicationSecret, "iv", ByteArray(0), suite.ivLen, suite),
            clientWriteKey = hkdfExpandLabel(clientApplicationSecret, "key", ByteArray(0), suite.keyLen, suite),
            clientWriteIv = hkdfExpandLabel(clientApplicationSecret, "iv", ByteArray(0), suite.ivLen, suite),
            cipherSuite = suite,
        )
    }

    fun finishedVerifyData(
        trafficSecret: ByteArray,
        transcriptHash: ByteArray,
        cipherSuite: CipherSuite,
    ): ByteArray {
        return hmac(
            hkdfExpandLabel(trafficSecret, "finished", ByteArray(0), cipherSuite.hashLength, cipherSuite),
            transcriptHash,
            cipherSuite,
        )
    }

    fun verifyClientFinished(
        message: ByteArray,
        secrets: HandshakeSecrets,
        expectedTranscriptHash: ByteArray,
    ): Boolean = runCatching {
        require(message.size >= 4 && (message[0].toInt() and 0xFF) == TLS_HANDSHAKE_FINISH_CONTENT_TYPE)
        val length = ((message[1].toInt() and 0xFF) shl 16) or
            ((message[2].toInt() and 0xFF) shl 8) or
            (message[3].toInt() and 0xFF)
        require(length == message.size - 4)
        require(length == secrets.cipherSuite.hashLength)
        val finishedKey = hkdfExpandLabel(
            secrets.clientHandshakeTrafficSecret,
            "finished",
            ByteArray(0),
            secrets.cipherSuite.hashLength,
            secrets.cipherSuite,
        )
        val expected = hmac(finishedKey, expectedTranscriptHash, secrets.cipherSuite)
        MessageDigest.isEqual(expected, message.copyOfRange(4, message.size))
    }.getOrDefault(false)
}
