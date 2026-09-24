package org.givashot.tls

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
fun deriveHandshakeSecrets(
    clientHello: ClientHelloWrapper,
    serverHello: ServerHelloWrapper,
    sharedSecret: ByteArray,
    cipherSuite: CipherSuite
): HandshakeSecrets {
    require(sharedSecret.size == 32) { "X25519 shared secret must be 32 bytes" }
    require(serverHello.cipherSuite.id == cipherSuite.id) { "Cipher suite mismatch" }

    val zero = ByteArray(cipherSuite.hashLength)
    val earlySecret = hkdfExtract(zero, ByteArray(0), cipherSuite)
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
    val masterSecret = hkdfExtract(derivedHandshakeSecret, ByteArray(0), cipherSuite)

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

///**
// * Encrypt handshake messages
// *
// * @param messages // 每条完整 Handshake 消息（含 type + length
// * @param secrets
// * @param sequenceNumber the sequence number
// * @return the byte arrays, 每个元素是完整的 TLSCiphertext record
// */
//fun encryptHandshakeMessages(
//    messages: List<ByteArray>,
//    secrets: HandshakeSecrets,
//    sequenceNumber: Long = 0L
//): List<ByteArray> {
//
//}

/**
 * Encrypt server flight according to the observed TLS record profile.
 *
 * The handshake messages are split as one continuous byte stream. A handshake
 * message may therefore span multiple records, while padding is kept outside
 * the transcript by the TLS record layer.
 */
fun encryptServerFlight(
    encryptedExtensions: ByteArray,
    certificate: ByteArray,
    certificateVerify: ByteArray,
    finished: ByteArray,
    secrets: HandshakeSecrets,
    recordLengths: List<Int>,
    sequenceNumber: Long = 0,
): List<ByteArray> {
    val flight = encryptedExtensions + certificate + certificateVerify + finished
    require(recordLengths.isNotEmpty()) { "TLS handshake record profile is empty" }

    var offset = 0
    return recordLengths.mapIndexed { index, targetLength ->
        require(targetLength in 17..0xFFFF) {
            "Invalid TLS handshake record length: $targetLength"
        }
        require(sequenceNumber <= Long.MAX_VALUE - index) {
            "TLS handshake sequence number overflow"
        }

        val plaintextCapacity = targetLength - 17
        val plaintextLength = minOf(plaintextCapacity, flight.size - offset)
        val paddingLength = plaintextCapacity - plaintextLength
        val plaintext = flight.copyOfRange(offset, offset + plaintextLength)
        offset += plaintextLength

        encryptTlsRecord(
            contentType = 22,
            plaintext = plaintext,
            writeKey = secrets.serverWriteKey,
            writeIv = secrets.serverWriteIv,
            sequenceNumber = sequenceNumber + index,
            cipherSuite = secrets.cipherSuite,
            paddingLength = paddingLength,
        )
    }.also {
        require(offset == flight.size) {
            "TLS handshake record profile cannot contain the server flight"
        }
    }
}

fun buildFinishedMessage(
    trafficSecret: ByteArray,
    transcriptHash: ByteArray,
    cipherSuite: CipherSuite,
): ByteArray {
    val finishedKey = hkdfExpandLabel(
        trafficSecret,
        "finished",
        ByteArray(0),
        cipherSuite.hashLength,
        cipherSuite,
    )
    return tlsHandshakeMessage(
        type = 20,
        body = hmac(finishedKey, transcriptHash, cipherSuite),
    )
}

fun decryptHandshakeRecord(
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
    require(decrypted.contentType == 22) { "Expected encrypted handshake record" }
    return decrypted.payload
}

fun verifyAndDecryptClientFinished(
    encryptedRecord: ByteArray,
    secrets: HandshakeSecrets,
    expectedTranscriptHash: ByteArray,
    sequenceNumber: Long,
): ByteArray? {
    return runCatching {
        val message = decryptHandshakeRecord(encryptedRecord, secrets, sequenceNumber)
        require(message.size >= 4 && message[0].toInt() and 0xFF == 20)
        val length = ((message[1].toInt() and 0xFF) shl 16) or
                ((message[2].toInt() and 0xFF) shl 8) or
                (message[3].toInt() and 0xFF)
        require(length == message.size - 4)
        val finishedKey = hkdfExpandLabel(
            secrets.clientHandshakeTrafficSecret,
            "finished",
            ByteArray(0),
            secrets.cipherSuite.hashLength,
            secrets.cipherSuite,
        )
        val expected = hmac(finishedKey, expectedTranscriptHash, secrets.cipherSuite)
        require(MessageDigest.isEqual(expected, message.copyOfRange(4, message.size)))
        message
    }.getOrNull()
}
