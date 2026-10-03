package org.givashot.tls.handshake

import org.givashot.tls.constant.TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH
import org.givashot.tls.crypto.ApplicationSecrets
import org.givashot.tls.crypto.HandshakeSecrets
import org.givashot.tls.crypto.Tls13KeySchedule

/** Everything the TLS 1.3 server handshake accumulates. Knows nothing about records or connection lifecycle. */
internal class HandshakeState {
    val clientHelloDecoder = HandshakeMessageDecoder(TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH)
    val clientFinishedDecoder = HandshakeMessageDecoder()
    val transcript = TranscriptHash()

    var clientHello: ClientHelloWrapper? = null
    var negotiated: NegotiatedParameters? = null
    var keySchedule: Tls13KeySchedule? = null
    var handshakeSecrets: HandshakeSecrets? = null
    var applicationSecrets: ApplicationSecrets? = null

    /** Transcript hash through the server Finished; used to verify the client Finished. */
    var serverFinishedTranscriptHash: ByteArray? = null

    fun reset() {
        clientHelloDecoder.reset()
        clientFinishedDecoder.reset()
        clientHello = null
        negotiated = null
        keySchedule = null
        handshakeSecrets = null
        applicationSecrets = null
        serverFinishedTranscriptHash = null
    }
}
