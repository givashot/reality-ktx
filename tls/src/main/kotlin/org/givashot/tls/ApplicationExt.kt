package org.givashot.tls

/**
 * Derive application secrets
 *
 * @param handshakeSecrets the handshake secrets
 * @param transcriptHashAfterServerFinished hash of ClientHello through server Finished
 * @return the application secrets to encrypt or decrypt application level data
 */
fun deriveApplicationSecrets(
    handshakeSecrets: HandshakeSecrets,
    transcriptHashAfterServerFinished: ByteArray,
): ApplicationSecrets {
    require(transcriptHashAfterServerFinished.size == handshakeSecrets.cipherSuite.hashLength)
    val suite = handshakeSecrets.cipherSuite
    val clientApplicationSecret = hkdfExpandLabel(
        handshakeSecrets.masterSecret,
        "c ap traffic",
        transcriptHashAfterServerFinished,
        suite.hashLength,
        suite,
    )
    val serverApplicationSecret = hkdfExpandLabel(
        handshakeSecrets.masterSecret,
        "s ap traffic",
        transcriptHashAfterServerFinished,
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

/**
 * Encrypt application data
 *
 * @param plaintext
 * @param appSecrets the app secrets
 * @param sequenceNumber the sequence number
 * @return the byte array
 */
fun encryptApplicationData(
    plaintext: ByteArray,
    appSecrets: ApplicationSecrets,
    sequenceNumber: Long
): ByteArray {
    return encryptTlsRecord(
        contentType = 23,
        plaintext = plaintext,
        writeKey = appSecrets.serverWriteKey,
        writeIv = appSecrets.serverWriteIv,
        sequenceNumber = sequenceNumber,
        cipherSuite = appSecrets.cipherSuite,
    )
}

/**
 * Decrypt application data
 *
 * @param plaintext
 * @param appSecrets the app secrets
 * @param sequenceNumber the sequence number
 * @return the byte array
 */
fun decryptApplicationData(
    plaintext: ByteArray,
    appSecrets: ApplicationSecrets,
    sequenceNumber: Long
): ByteArray {
    val decrypted = decryptTlsRecord(
        plaintext,
        appSecrets.clientWriteKey,
        appSecrets.clientWriteIv,
        sequenceNumber,
        appSecrets.cipherSuite,
    )
    require(decrypted.contentType == 23) { "Expected application data record" }
    return decrypted.payload
}
