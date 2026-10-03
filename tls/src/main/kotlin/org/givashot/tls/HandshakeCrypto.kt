package org.givashot.tls

import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE
import org.givashot.tls.constant.TLS_HANDSHAKE_FINISH_CONTENT_TYPE
import org.givashot.tls.entity.handshake.CipherSuite
import org.givashot.tls.entity.handshake.ClientHelloWrapper
import org.givashot.tls.entity.handshake.HandshakeSecrets
import org.givashot.tls.entity.handshake.ServerHelloWrapper
import java.security.MessageDigest

/**
 * Derive handshake secrets
 *
 * @param clientHello the client hello
 * @param serverHello the server hello
 * @param sharedSecret the shared secret
 * @param cipherSuite the cipher suite
 * @return the handshake secrets
 */
internal fun deriveHandshakeSecrets(
    clientHello: ClientHelloWrapper,
    serverHello: ServerHelloWrapper,
    sharedSecret: ByteArray,
    cipherSuite: CipherSuite
): HandshakeSecrets {
    require(sharedSecret.size == 32) { "X25519 shared secret must be 32 bytes" }
    require(serverHello.cipherSuite.id == cipherSuite.id) { "Cipher suite mismatch" }

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
    val transcript = clientHello.handshakeAndBody + serverHello.base.encodeHandshake()
    val transcriptHash = digest(transcript, cipherSuite)
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

internal fun decryptHandshakeRecord(
    encryptedRecord: ByteArray,
    secrets: HandshakeSecrets,
    sequenceNumber: Long,
): ByteArray {
    val decrypted = decryptTlsRecord(
        encryptedRecord,
        secrets.clientWriteKey,
        secrets.clientWriteIv,
        sequenceNumber,
        secrets.cipherSuite,
    )
    require(decrypted.contentType == TLS_HANDSHAKE_CONTENT_TYPE) { "Expected encrypted handshake record" }
    return decrypted.payload
}


/**
 *  Verifies a complete Client Finished handshake message after its TLS records are reassembled.
 */
internal fun verifyClientFinishedMessage(
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
