package org.givashot.tls

import org.givashot.tls.constant.TLS_APPLICATION_DATA_CONTENT_TYPE
import org.givashot.tls.entity.ApplicationSecrets
import org.givashot.tls.entity.handshake.HandshakeSecrets

/**
 * Derive application secrets
 *
 * @param handshakeSecrets the handshake secrets
 * @param transcriptHashAfterServerFinished hash of ClientHello through server Finished
 * @return the application secrets to encrypt or decrypt application level data
 */
internal fun deriveApplicationSecrets(
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
 * Decrypts one client application data record.
 *
 * @param encodedRecord the encrypted TLS record
 * @param appSecrets the traffic keys derived for this connection
 * @param sequenceNumber the client application record sequence number
 * @return the decrypted application payload
 */
internal fun decryptApplicationData(
    encodedRecord: ByteArray,
    appSecrets: ApplicationSecrets,
    sequenceNumber: Long
): ByteArray {
    val decrypted = decryptTlsRecord(
        encodedRecord,
        appSecrets.clientWriteKey,
        appSecrets.clientWriteIv,
        sequenceNumber,
        appSecrets.cipherSuite,
    )
    require(decrypted.contentType == TLS_APPLICATION_DATA_CONTENT_TYPE) { "Expected application data record" }
    return decrypted.payload
}
