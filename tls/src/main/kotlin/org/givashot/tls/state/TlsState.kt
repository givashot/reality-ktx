package org.givashot.tls.state

/** Which stage of the TLS connection lifecycle we are in. Holds no secrets, transcripts or record state. */
sealed interface TlsState {
    data object AwaitClientHello : TlsState

    /** ClientHello parsed and negotiated; waiting for the application to authenticate and request the server flight. */
    data object ProcessingClientHello : TlsState

    /** Server flight sent; waiting for client Finished. */
    data object AwaitClientFinished : TlsState

    data object Established : TlsState

    data class Closed(val error: Throwable?) : TlsState
}
