package org.givashot.tls.connection

sealed interface TlsConnectionResult {
    /** Events are for the application; outbound holds encoded TLS records to write to the peer. */
    data class Ok(
        val events: List<TlsEvent> = emptyList(),
        val outbound: List<ByteArray> = emptyList(),
    ) : TlsConnectionResult

    /** Protocol errors may still carry a fatal alert that must be written before closing the transport. */
    data class Err(
        val error: TlsError,
        val outbound: List<ByteArray> = emptyList(),
    ) : TlsConnectionResult
}
