package org.givashot.tls.state

import org.givashot.tls.connection.TlsError

enum class TlsAlert(val code: Int) {
    UNEXPECTED_MESSAGE(10),
    BAD_RECORD_MAC(20),
    HANDSHAKE_FAILURE(40),
    ILLEGAL_PARAMETER(47),
    DECODE_ERROR(50),
    DECRYPT_ERROR(51),
    INTERNAL_ERROR(80);

    companion object {
        internal fun forError(error: TlsError.Peer): TlsAlert = when (error) {
            is TlsError.Peer.UnexpectedContentType,
            is TlsError.Peer.UnexpectedHandshakeType,
            is TlsError.Peer.UnexpectedExtraHandshakeData,
            is TlsError.Peer.InvalidChangeCipherSpec -> UNEXPECTED_MESSAGE
            is TlsError.Peer.ClientHelloTooLarge,
            is TlsError.Peer.MalformedClientHello -> DECODE_ERROR
            is TlsError.Peer.NegotiationFailed -> HANDSHAKE_FAILURE
            TlsError.Peer.ClientFinishedVerificationFailed -> DECRYPT_ERROR
            is TlsError.Peer.ProcessingFailure -> ILLEGAL_PARAMETER
        }
    }
}
