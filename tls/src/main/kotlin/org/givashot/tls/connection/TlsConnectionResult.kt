package org.givashot.tls.connection

sealed interface TlsConnectionResult {
    /** Events are for the application; outbound holds encoded TLS records to write to the peer. */
    data class Ok(
        val events: List<TlsEvent> = emptyList(),
        val outbound: List<ByteArray> = emptyList(),
    ) : TlsConnectionResult

    data class Err(val error: TlsError) : TlsConnectionResult
}
