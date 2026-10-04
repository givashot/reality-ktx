package org.givashot.tls.handshake

import org.givashot.tls.constant.TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH
import org.givashot.tls.crypto.ApplicationTrafficSecrets
import org.givashot.tls.crypto.HandshakeTrafficSecrets
import org.givashot.tls.crypto.Tls13KeySchedule

/** Everything the TLS 1.3 server handshake accumulates. Knows nothing about records or connection lifecycle. */
internal class HandshakeState {
    val clientHelloDecoder = HandshakeMessageDecoder(TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH)
    val clientFinishedDecoder = HandshakeMessageDecoder()
    val transcript = TranscriptHash()

    var clientHello: ClientHelloWrapper? = null
    var negotiated: NegotiatedParameters? = null
    var keySchedule: Tls13KeySchedule? = null
    var handshakeTrafficSecrets: HandshakeTrafficSecrets? = null
    var applicationTrafficSecrets: ApplicationTrafficSecrets? = null

    /** Transcript hash through the server Finished; used to verify the client Finished. */
    var serverFinishedTranscriptHash: ByteArray? = null

    fun reset() {
        clientHelloDecoder.reset()
        clientFinishedDecoder.reset()
        clientHello = null
        negotiated = null
        keySchedule = null
        handshakeTrafficSecrets = null
        applicationTrafficSecrets = null
        serverFinishedTranscriptHash = null
    }
}
