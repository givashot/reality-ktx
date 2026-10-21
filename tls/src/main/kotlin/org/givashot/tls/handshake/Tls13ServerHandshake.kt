package org.givashot.tls.handshake

import org.givashot.tls.ServerProfile
import org.givashot.tls.connection.ClientFinishedVerificationFailedException
import org.givashot.tls.connection.UnexpectedExtraHandshakeDataException
import org.givashot.tls.crypto.ApplicationTrafficSecrets
import org.givashot.tls.crypto.HandshakeTrafficSecrets
import org.givashot.tls.crypto.Tls13KeySchedule
import org.givashot.tls.crypto.TrafficKeys

/**
 * TLS 1.3 server handshake orchestration: negotiation, transcript, and driving the [Tls13KeySchedule] and
 * [Tls13HandshakeCodec] in the right order. It does not decide whether a message is allowed in the current
 * state (state machine), and does not frame or protect records (record layer).
 */
internal class Tls13ServerHandshake(
    private val profile: ServerProfile,
    private val codec: Tls13HandshakeCodec = Tls13HandshakeCodec(),
    private val state: HandshakeState = HandshakeState(),
) {
    val handshakeTrafficSecrets: HandshakeTrafficSecrets
        get() = checkNotNull(state.handshakeTrafficSecrets) { "Handshake secrets are not available yet" }

    val applicationTrafficSecrets: ApplicationTrafficSecrets
        get() = checkNotNull(state.applicationTrafficSecrets) { "Application secrets are not available yet" }

    fun reset() {
        state.reset()
        codec.reset()
    }

    /** Returns the complete ClientHello message, or null while more data is needed. */
    fun receiveClientHelloFragment(fragment: ByteArray): HandshakeMessage? =
        singleMessage("ClientHello", codec.feedClientHello(fragment), codec.clientHelloPendingBytes)

    /** Returns the next complete post-ClientHello message, or null while more data is needed. */
    fun receiveFragment(fragment: ByteArray): HandshakeMessage? =
        singleMessage("handshake message", codec.feed(fragment), codec.pendingBytes)

    fun onClientHello(message: HandshakeMessage): ClientHelloWrapper =
        codec.parseClientHello(message).also { state.clientHello = it }

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
        val hello = checkNotNull(state.clientHello) { "ClientHello has not been received" }
        val negotiated = checkNotNull(state.negotiated) { "Parameters have not been negotiated" }
        val suite = negotiated.cipherSuite
        val transcript = state.transcript

        val serverHello = newServerHello(hello, negotiated)
        val serverHelloBytes = codec.encodeServerHello(serverHello.base)
        transcript.update(serverHelloBytes)

        val keySchedule = Tls13KeySchedule(suite)
        keySchedule.deriveEarlySecret()
        keySchedule.deriveHandshakeSecret(serverHello.sharedSecret)
        val handshakeSecrets = keySchedule.handshakeTrafficSecrets(transcript.hash(suite))

        val extensionsBytes = codec.encodeEncryptedExtensions(encryptedExtensions)
        transcript.update(extensionsBytes)
        val certificateBytes = codec.encodeCertificate(certificate)
        transcript.update(certificateBytes)
        val certificateVerifyBytes = codec.encodeCertificateVerify(certificate, transcript.hash(suite))
        transcript.update(certificateVerifyBytes)
        val finishedBytes = codec.encodeFinished(
            keySchedule.finishedVerifyData(handshakeSecrets.serverHandshakeTrafficSecret, transcript.hash(suite))
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

    /** Verifies the client Finished and appends it to the transcript. Throws if it does not verify. */
    fun onClientFinished(message: HandshakeMessage) {
        val keySchedule = checkNotNull(state.keySchedule) { "Server flight has not been built" }
        val negotiated = checkNotNull(state.negotiated) { "Parameters have not been negotiated" }
        val verifyData = codec.parseFinished(message, negotiated.cipherSuite.hashLength)
        val verified = keySchedule.verifyFinished(
            handshakeTrafficSecrets.clientHandshakeTrafficSecret,
            checkNotNull(state.serverFinishedTranscriptHash),
            verifyData,
        )
        if (!verified) throw ClientFinishedVerificationFailedException()
        state.transcript.update(message.encodedBytes)
    }

    fun onKeyUpdate(message: HandshakeMessage): KeyUpdate = codec.parseKeyUpdate(message)

    fun encodeKeyUpdate(requestPeer: Boolean): ByteArray = codec.encodeKeyUpdate(requestPeer)

    /** Next generation of [current] traffic keys; the record layer decides when to switch to it. */
    fun nextTrafficKeys(current: TrafficKeys): TrafficKeys =
        checkNotNull(state.keySchedule) { "Key schedule is not available yet" }.nextTrafficKeys(current)

    /**
     * A handshake message must not share a record with data that follows it under a key change (RFC 8446 section 5.1),
     * so exactly one complete message with no trailing bytes is accepted per fragment.
     */
    private fun singleMessage(context: String, messages: List<HandshakeMessage>, pendingBytes: Int): HandshakeMessage? {
        if (messages.size > 1 || (messages.isNotEmpty() && pendingBytes != 0)) {
            throw UnexpectedExtraHandshakeDataException(context)
        }
        return messages.singleOrNull()
    }
}
