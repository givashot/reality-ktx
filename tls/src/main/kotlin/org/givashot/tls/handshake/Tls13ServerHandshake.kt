package org.givashot.tls.handshake

import org.givashot.tls.ServerProfile
import org.givashot.tls.crypto.ApplicationSecrets
import org.givashot.tls.crypto.HandshakeSecrets
import org.givashot.tls.crypto.KeySchedule
import org.givashot.tls.crypto.digest

internal data class ServerFlight(
    val serverHello: ByteArray,
    val encryptedHandshake: ByteArray,
    val transcript: ByteArray,
    val transcriptHash: ByteArray,
    val handshakeSecrets: HandshakeSecrets,
    val applicationSecrets: ApplicationSecrets,
)

/** Builds the TLS 1.3 server flight and derives the traffic secrets it establishes. */
internal class Tls13ServerHandshake {
    fun buildFlight(
        clientHello: ClientHelloWrapper,
        encryptedExtensions: EncryptedExtensionsData,
        certificate: CertificateData,
        profile: ServerProfile,
    ): ServerFlight {
        require(certificate.certificateChain.isNotEmpty()) { "Server certificate chain is empty" }

        val transcript = clientHello.handshakeAndBody
        val serverHello = newServerHello(clientHello, profile)
        val serverHelloBytes = serverHello.base.encodeHandshake()
        val transcriptHash = digest(transcript + serverHelloBytes, serverHello.cipherSuite)
        val handshakeSecrets = KeySchedule.deriveHandshakeSecrets(
            sharedSecret = serverHello.sharedSecret,
            transcriptHash = transcriptHash,
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
        val nextTranscript = transcript + serverHelloBytes + encryptedHandshake
        val nextTranscriptHash = digest(nextTranscript, serverHello.cipherSuite)
        val appSecrets = KeySchedule.deriveApplicationSecrets(handshakeSecrets, nextTranscriptHash)
        return ServerFlight(
            serverHello = serverHelloBytes,
            encryptedHandshake = encryptedHandshake,
            transcript = nextTranscript,
            transcriptHash = nextTranscriptHash,
            handshakeSecrets = handshakeSecrets,
            applicationSecrets = appSecrets,
        )
    }
}
