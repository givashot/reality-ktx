package org.givashot.tls.state

import org.givashot.tls.connection.TlsError
import org.givashot.tls.constant.TLS_CONTENT_TYPE_ALERT
import org.givashot.tls.constant.TLS_CONTENT_TYPE_APPLICATION_DATA_
import org.givashot.tls.constant.TLS_CONTENT_TYPE_HANDSHAKE
import org.givashot.tls.record.TlsRecordEvent

/** The state machine's verdict on a record event. */
internal sealed interface TlsDecision {
    data object Ignore : TlsDecision
    class HandshakeFragment(val payload: ByteArray) : TlsDecision
    class ApplicationData(val payload: ByteArray) : TlsDecision
    class Alert(val payload: ByteArray) : TlsDecision
    data class Reject(val error: TlsError.Peer) : TlsDecision
}

internal class TlsStateMachine(initialState: TlsState = TlsState.AwaitClientHello) {
    private var state: TlsState = initialState

    fun currentState(): TlsState = state

    fun transitionTo(next: TlsState) {
        check(isValidTransition(state, next)) { "Invalid TLS state transition: $state -> $next" }
        state = next
    }

    /**
     * Decides whether [event] is permitted in the current state. Pure: does not transition and never inspects
     * handshake or alert bytes; the caller acts on the decision.
     */
    fun accept(event: TlsRecordEvent): TlsDecision {
        val phase = state.toString()
        check(!state.shutdown()) { "Record event in state $phase" }
        val acceptsHandshake = state == TlsState.AwaitClientHello ||
                state == TlsState.AwaitClientHandshake || state == TlsState.AwaitClientFinished
        val acceptsCcs = state == TlsState.ProcessingClientHello ||
                state == TlsState.AwaitClientHandshake || state == TlsState.AwaitClientFinished
        val acceptsApplicationData = state == TlsState.Established

        return when (event) {
            TlsRecordEvent.CompatibilityCcs ->
                if (acceptsCcs) TlsDecision.Ignore
                else TlsDecision.Reject(TlsError.Peer.InvalidChangeCipherSpec("unexpected ChangeCipherSpec in state $phase"))

            is TlsRecordEvent.Empty -> when {
                event.type == TLS_CONTENT_TYPE_ALERT -> TlsDecision.Reject(TlsError.Peer.MalformedAlert(0))
                event.type == TLS_CONTENT_TYPE_APPLICATION_DATA_ && acceptsApplicationData -> TlsDecision.Ignore
                else -> TlsDecision.Reject(TlsError.Peer.UnexpectedRecord(event.type, phase))
            }

            is TlsRecordEvent.Content -> when (event.type) {
                TLS_CONTENT_TYPE_ALERT -> TlsDecision.Alert(event.payload)
                TLS_CONTENT_TYPE_HANDSHAKE -> when {
                    acceptsHandshake -> TlsDecision.HandshakeFragment(event.payload)
                    state == TlsState.Established ->
                        TlsDecision.Reject(
                            TlsError.Peer.UnexpectedContentType(
                                TLS_CONTENT_TYPE_APPLICATION_DATA_,
                                event.type,
                                phase
                            )
                        )

                    else -> TlsDecision.Reject(TlsError.Peer.UnexpectedRecord(event.type, phase))
                }

                TLS_CONTENT_TYPE_APPLICATION_DATA_ -> when {
                    acceptsApplicationData -> TlsDecision.ApplicationData(event.payload)
                    acceptsHandshake ->
                        TlsDecision.Reject(
                            TlsError.Peer.UnexpectedContentType(
                                TLS_CONTENT_TYPE_HANDSHAKE,
                                event.type,
                                phase
                            )
                        )

                    else -> TlsDecision.Reject(TlsError.Peer.UnexpectedRecord(event.type, phase))
                }

                else -> TlsDecision.Reject(TlsError.Peer.UnexpectedRecord(event.type, phase))
            }
        }
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

fun TlsState.shutdown() = this is TlsState.Closed || this is TlsState.Failed