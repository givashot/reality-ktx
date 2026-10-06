package org.givashot.tls.connection

/** Errors returned explicitly by [TlsConnection]; they are never propagated as exceptions to callers. */
sealed interface TlsError {
    val description: String

    /** Caused by the remote peer. The connection moves to the Failed state. */
    sealed interface Peer : TlsError {
        data class UnexpectedContentType(val expected: Int, val actual: Int, val phase: String) : Peer {
            override val description get() = "Unexpected content type $actual (expected $expected) in $phase"
        }

        data class UnexpectedHandshakeType(val expected: Int, val actual: Int) : Peer {
            override val description get() = "Unexpected handshake type $actual (expected $expected)"
        }

        data class UnexpectedExtraHandshakeData(val context: String) : Peer {
            override val description get() = "Unexpected extra handshake data: $context"
        }

        data class ClientHelloTooLarge(val size: Int, val limit: Int) : Peer {
            override val description get() = "ClientHello size $size exceeds limit $limit"
        }

        data class MalformedClientHello(val reason: String) : Peer {
            override val description get() = "Malformed ClientHello: $reason"
        }

        data class NegotiationFailed(val reason: String) : Peer {
            override val description get() = "TLS negotiation failed: $reason"
        }

        data class InvalidChangeCipherSpec(val reason: String) : Peer {
            override val description get() = "Invalid ChangeCipherSpec: $reason"
        }

        data class TooManyEmptyRecords(val limit: Int) : Peer {
            override val description get() = "More than $limit consecutive empty records"
        }

        data class MalformedAlert(val length: Int) : Peer {
            override val description get() = "Malformed alert of length $length"
        }

        data class UnexpectedRecord(val type: Int, val phase: String) : Peer {
            override val description get() = "Unexpected record of type $type in $phase"
        }

        data class AlertReceived(val alertCode: Int) : Peer {
            override val description get() = "Peer sent fatal alert $alertCode"
        }

        data object BadRecordMac : Peer {
            override val description get() = "Record decryption failed"
        }

        data object ClientFinishedVerificationFailed : Peer {
            override val description get() = "Client Finished verification failed"
        }

        data class ProcessingFailure(val cause: Throwable) : Peer {
            override val description get() = "TLS processing failed: ${cause.message}"
        }
    }

    /** Caused by API misuse. Does not change the connection state. */
    sealed interface Usage : TlsError {
        data class InvalidState(val operation: String, val state: String) : Usage {
            override val description get() = "$operation is not valid in state $state"
        }

        data class InvalidArgument(val reason: String) : Usage {
            override val description get() = reason
        }

        data object ConnectionClosed : Usage {
            override val description get() = "TLS connection is closed"
        }

        data class ConnectionFailed(val cause: Peer) : Usage {
            override val description get() = "TLS connection already failed: ${cause.description}"
        }
    }
}

/** Thrown by the handshake layer for protocol violations; TlsConnection converts it into a [TlsError.Peer]. */
internal class TlsProtocolException(val error: TlsError.Peer) : RuntimeException(error.description)
