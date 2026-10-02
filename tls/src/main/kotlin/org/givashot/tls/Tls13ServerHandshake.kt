package org.givashot.tls

import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE
import org.givashot.tls.entity.ApplicationSecrets
import org.givashot.tls.entity.handshake.ClientHelloWrapper
import org.givashot.tls.entity.handshake.CertificateData
import org.givashot.tls.entity.handshake.EncryptedExtensionsData
import org.givashot.tls.entity.handshake.HandshakeSecrets

internal data class ServerFlightResult(
    val records: List<ByteArray>,
    val transcript: ByteArray,
    val transcriptHash: ByteArray,
    val handshakeSecrets: HandshakeSecrets,
    val applicationSecrets: ApplicationSecrets,
)

/** Builds the TLS 1.3 server flight and derives the traffic secrets it establishes. */
internal class Tls13ServerHandshake {
    fun buildFlight(
        clientHello: ClientHelloWrapper,
        transcript: ByteArray,
        encryptedExtensions: EncryptedExtensionsData,
        certificate: CertificateData,
        recordLengths: List<Int>,
        recordProtector: TlsRecordProtector,
    ): ServerFlightResult {
        require(certificate.certificateChain.isNotEmpty()) { "Server certificate chain is empty" }

        val serverHello = newServerHello(clientHello)
        val serverHelloBytes = serverHello.base.encodeHandshake()
        val handshakeSecrets = deriveHandshakeSecrets(
            clientHello = clientHello,
            serverHello = serverHello,
            sharedSecret = serverHello.sharedSecret,
            cipherSuite = serverHello.cipherSuite,
        )

        val extensionsBytes = encodeEncryptedExtensions(encryptedExtensions.extensions)
        val certificateBytes = encodeCertificate(certificate)
        val transcriptBeforeCertificateVerify = transcript + serverHelloBytes + extensionsBytes + certificateBytes
        val certificateVerifyBytes = encodeCertificateVerify(
            certificate,
            digest(transcriptBeforeCertificateVerify, serverHello.cipherSuite),
        )
        val transcriptBeforeFinished = transcriptBeforeCertificateVerify + certificateVerifyBytes
        val finishedBytes = buildFinishedMessage(
            handshakeSecrets.serverHandshakeTrafficSecret,
            digest(transcriptBeforeFinished, serverHello.cipherSuite),
            serverHello.cipherSuite,
        )
        val encryptedHandshake = extensionsBytes + certificateBytes + certificateVerifyBytes + finishedBytes
        val encryptedRecords = recordProtector.encryptHandshakeFlight(
            flight = encryptedHandshake,
            secrets = handshakeSecrets,
            recordLengths = recordLengths,
        )
        val nextTranscript = transcript + serverHelloBytes + encryptedHandshake
        val nextTranscriptHash = digest(nextTranscript, serverHello.cipherSuite)
        val appSecrets = deriveApplicationSecrets(handshakeSecrets, nextTranscriptHash)
        return ServerFlightResult(
            records = listOf(tlsRecord(TLS_HANDSHAKE_CONTENT_TYPE, serverHelloBytes)) + encryptedRecords,
            transcript = nextTranscript,
            transcriptHash = nextTranscriptHash,
            handshakeSecrets = handshakeSecrets,
            applicationSecrets = appSecrets,
        )
    }
}
