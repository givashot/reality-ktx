package org.givashot.tls.handshake

import org.givashot.tls.ServerProfile
import org.givashot.tls.connection.TlsError
import org.givashot.tls.connection.TlsProtocolException
import org.givashot.tls.constant.TLS_HANDSHAKE_CLIENT_HELLO_CONTENT_TYPE
import org.givashot.tls.constant.TLS_HANDSHAKE_FINISH_CONTENT_TYPE
import org.givashot.tls.constant.TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH
import org.givashot.tls.crypto.ApplicationTrafficSecrets
import org.givashot.tls.crypto.HandshakeTrafficSecrets
import org.givashot.tls.crypto.Tls13KeySchedule

internal class ServerFlight(
    val serverHello: ByteArray,
    val encodedHandshakes: ByteArray,
)

/**
 * TLS 1.3 server handshake: negotiation, transcript, key schedule and handshake messages.
 * Produces handshake bytes and secrets; framing, protection and lifecycle belong to other components.
 */
internal class Tls13ServerHandshake(
    private val profile: ServerProfile,
    private val state: HandshakeState = HandshakeState(),
) {
    val handshakeTrafficSecrets: HandshakeTrafficSecrets
        get() = checkNotNull(state.handshakeTrafficSecrets) { "Handshake secrets are not available yet" }

    val applicationTrafficSecrets: ApplicationTrafficSecrets
        get() = checkNotNull(state.applicationTrafficSecrets) { "Application secrets are not available yet" }

    fun reset() = state.reset()

    /** Returns the parsed ClientHello once a complete message has arrived, null while more data is needed. */
    fun onClientHelloFragment(fragment: ByteArray): ClientHelloWrapper? {
        val messages = state.clientHelloDecoder.feed(fragment)
        if (messages.size > 1 || (messages.isNotEmpty() && state.clientHelloDecoder.bufferedByteCount != 0)) {
            throw TlsProtocolException(TlsError.Peer.UnexpectedExtraHandshakeData("ClientHello"))
        }
        val message = messages.singleOrNull() ?: return null
        if (message.type != TLS_HANDSHAKE_CLIENT_HELLO_CONTENT_TYPE) {
            throw TlsProtocolException(
                TlsError.Peer.UnexpectedHandshakeType(TLS_HANDSHAKE_CLIENT_HELLO_CONTENT_TYPE, message.type),
            )
        }
        if (message.encodedBytes.size > TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH) {
            throw TlsProtocolException(
                TlsError.Peer.ClientHelloTooLarge(message.encodedBytes.size, TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH),
            )
        }
        return ClientHelloWrapper.parse(message.encodedBytes).also { state.clientHello = it }
    }

    /** Cheap negotiation only: no key generation, so a failure can still fall back to the real site. */
    fun processClientHello() {
        val hello = checkNotNull(state.clientHello) { "ClientHello has not been received" }
        state.negotiated = negotiate(hello, profile)
        state.transcript.update(hello.handshakeAndBody)
    }

    /** Generates ServerHello and the encrypted flight, and derives handshake and application secrets. */
    fun buildServerFlight(
        encryptedExtensions: EncryptedExtensionsData,
        certificate: CertificateData,
    ): ServerFlight {
        require(certificate.certificateChain.isNotEmpty()) { "Server certificate chain is empty" }
        val hello = checkNotNull(state.clientHello) { "ClientHello has not been received" }
        val negotiated = checkNotNull(state.negotiated) { "Parameters have not been negotiated" }
        val suite = negotiated.cipherSuite
        val transcript = state.transcript

        val serverHello = newServerHello(hello, negotiated)
        val serverHelloBytes = serverHello.base.encodeHandshake()
        transcript.update(serverHelloBytes)

        val keySchedule = Tls13KeySchedule(suite)
        keySchedule.deriveEarlySecret()
        keySchedule.deriveHandshakeSecret(serverHello.sharedSecret)
        val handshakeSecrets = keySchedule.handshakeTrafficSecrets(transcript.hash(suite))

        val extensionsBytes = encodeEncryptedExtensions(encryptedExtensions.extensions)
        transcript.update(extensionsBytes)
        val certificateBytes = encodeCertificate(certificate)
        transcript.update(certificateBytes)
        val certificateVerifyBytes = encodeCertificateVerify(certificate, transcript.hash(suite))
        transcript.update(certificateVerifyBytes)
        val finishedBytes = buildFinishedMessage(
            handshakeSecrets.serverHandshakeTrafficSecret,
            transcript.hash(suite),
            suite,
        )
        transcript.update(finishedBytes)

        val serverFinishedHash = transcript.hash(suite)
        keySchedule.deriveMasterSecret()

        state.keySchedule = keySchedule
        state.handshakeTrafficSecrets = handshakeSecrets
        state.applicationTrafficSecrets = keySchedule.applicationTrafficSecrets(serverFinishedHash)
        state.serverFinishedTranscriptHash = serverFinishedHash

        return ServerFlight(
            serverHello = serverHelloBytes,
            encodedHandshakes = extensionsBytes + certificateBytes + certificateVerifyBytes + finishedBytes,
        )
    }

    /** Returns true once a complete, valid client Finished has been verified, false while more data is needed. */
    fun onClientFinishedFragment(fragment: ByteArray): Boolean {
        val messages = state.clientFinishedDecoder.feed(fragment)
        if (messages.size > 1 || (messages.isNotEmpty() && state.clientFinishedDecoder.bufferedByteCount != 0)) {
            throw TlsProtocolException(TlsError.Peer.UnexpectedExtraHandshakeData("ClientFinished"))
        }
        val message = messages.singleOrNull() ?: return false
        if (message.type != TLS_HANDSHAKE_FINISH_CONTENT_TYPE) {
            throw TlsProtocolException(
                TlsError.Peer.UnexpectedHandshakeType(TLS_HANDSHAKE_FINISH_CONTENT_TYPE, message.type),
            )
        }
        val keySchedule = checkNotNull(state.keySchedule) { "Server flight has not been built" }
        val verified = keySchedule.verifyClientFinished(
            message.encodedBytes,
            handshakeTrafficSecrets.clientHandshakeTrafficSecret,
            checkNotNull(state.serverFinishedTranscriptHash),
        )
        if (!verified) throw TlsProtocolException(TlsError.Peer.ClientFinishedVerificationFailed)
        state.transcript.update(message.encodedBytes)
        return true
    }
}
