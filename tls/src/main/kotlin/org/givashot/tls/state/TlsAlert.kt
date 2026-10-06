package org.givashot.tls.state

import org.givashot.tls.connection.TlsError

enum class TlsAlert(val code: Int) {
    CLOSE_NOTIFY(0),
    UNEXPECTED_MESSAGE(10),
    BAD_RECORD_MAC(20),
    HANDSHAKE_FAILURE(40),
    ILLEGAL_PARAMETER(47),
    DECODE_ERROR(50),
    DECRYPT_ERROR(51),
    INTERNAL_ERROR(80),
    USER_CANCELED(90);

    companion object {
        const val CLOSE_NOTIFY_CODE = 0
        const val USER_CANCELED_CODE = 90

        /** The alert we would send for [error]; null when the peer already terminated the connection. */
        internal fun forError(error: TlsError.Peer): TlsAlert? = when (error) {
            is TlsError.Peer.AlertReceived -> null
            is TlsError.Peer.MalformedAlert -> DECODE_ERROR
            TlsError.Peer.BadRecordMac -> BAD_RECORD_MAC
            is TlsError.Peer.TooManyEmptyRecords,
            is TlsError.Peer.UnexpectedRecord,
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
