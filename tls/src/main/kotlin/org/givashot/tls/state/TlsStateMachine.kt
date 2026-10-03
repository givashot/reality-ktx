package org.givashot.tls.state

import org.givashot.tls.connection.TlsError

internal class TlsStateMachine(initialState: TlsState = TlsState.AwaitClientHello) {
    private var state: TlsState = initialState

    fun currentState(): TlsState = state

    fun transitionTo(next: TlsState) {
        check(isValidTransition(state, next)) { "Invalid TLS state transition: $state -> $next" }
        state = next
    }

    /** No-op when already Failed or Closed. */
    fun fail(error: TlsError.Peer) {
        if (state is TlsState.Failed || state is TlsState.Closed) return
        transitionTo(TlsState.Failed(TlsAlert.forError(error), error))
    }

    /** Idempotent. */
    fun close() {
        if (state is TlsState.Closed) return
        transitionTo(TlsState.Closed)
    }

    private fun isValidTransition(from: TlsState, to: TlsState): Boolean = when (to) {
        TlsState.AwaitClientHello -> false
        TlsState.ProcessingClientHello -> from == TlsState.AwaitClientHello
        TlsState.AwaitClientHandshake -> from == TlsState.ProcessingClientHello
        TlsState.AwaitClientFinished -> from == TlsState.AwaitClientHandshake
        TlsState.Established -> from == TlsState.AwaitClientFinished
        is TlsState.Failed -> from !is TlsState.Failed && from != TlsState.Closed
        TlsState.Closed -> true
    }
}
