package org.givashot.tls.session

/** 状态机显式返回的错误。不通过异常传播。 */
sealed interface TlsError {
    val description: String

    /** 对端行为导致的错误。产生后状态机进入 Failed 终态。 */
    sealed interface Peer : TlsError {
        data class UnexpectedContentType(val expected: Int, val actual: Int, val phase: String) : Peer {
            override val description get() = "Unexpected content type $actual (expected $expected) in $phase"
        }

        data class UnexpectedHandshakeType(val expected: Int, val actual: Int) : Peer {
            override val description get() = "Unexpected handshake type $actual (expected $expected)"
        }

        /** 一条记录里夹带了多条握手消息,或握手消息后还有多余数据。 */
        data class UnexpectedExtraHandshakeData(val context: String) : Peer {
            override val description get() = "Unexpected extra handshake data: $context"
        }

        data class ClientHelloTooLarge(val size: Int, val limit: Int) : Peer {
            override val description get() = "ClientHello size $size exceeds limit $limit"
        }

        data class MalformedClientHello(val reason: String) : Peer {
            override val description get() = "Malformed ClientHello: $reason"
        }

        data object ClientFinishedVerificationFailed : Peer {
            override val description get() = "Client Finished verification failed"
        }

        data class ProcessingFailure(val cause: Throwable) : Peer {
            override val description get() = "TLS processing failed: ${cause.message}"
        }
    }

    /** 调用方误用 API 导致的错误。不改变状态机状态(ConnectionClosed/ConnectionFailed 除外,它们本身就反映终态)。 */
    sealed interface Usage : TlsError {
        data class InvalidState(val operation: String, val phase: String) : Usage {
            override val description get() = "$operation is not valid in phase $phase"
        }

        data class InvalidArgument(val reason: String) : Usage {
            override val description get() = reason
        }

        data object InputWhileAwaitingServerFlight : Usage {
            override val description get() = "Server flight must be built before processing additional client data"
        }

        data object ConnectionClosed : Usage {
            override val description get() = "TLS connection is closed"
        }

        data class ConnectionFailed(val cause: Peer) : Usage {
            override val description get() = "TLS connection already failed: ${cause.description}"
        }
    }
}

sealed interface TlsResult<out T> {
    data class Ok<out T>(val value: T) : TlsResult<T>
    data class Err(val error: TlsError) : TlsResult<Nothing>
}

inline fun <T> TlsResult<T>.getOrElse(onError: (TlsResult.Err) -> T): T = when (this) {
    is TlsResult.Ok -> value
    is TlsResult.Err -> onError(this)
}
