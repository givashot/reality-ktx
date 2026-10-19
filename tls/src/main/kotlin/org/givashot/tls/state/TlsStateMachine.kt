package org.givashot.tls.state

import org.givashot.tls.connection.DecodeErrorException
import org.givashot.tls.connection.UnexpectMessageException
import org.givashot.tls.connection.UnexpectedContentTypeException
import org.givashot.tls.connection.UnexpectedRecordException
import org.givashot.tls.constant.TLS_CONTENT_TYPE_ALERT
import org.givashot.tls.constant.TLS_CONTENT_TYPE_APPLICATION_DATA_
import org.givashot.tls.constant.TLS_CONTENT_TYPE_HANDSHAKE
import org.givashot.tls.record.TlsRecordEvent

internal class TlsStateMachine(initialState: TlsState = TlsState.AwaitClientHello) {

    private var state: TlsState = initialState

    val closed: Boolean get() = state is TlsState.Closed

    fun currentState(): TlsState = state

    fun transitionTo(next: TlsState) {
        throwIfClosed("transition to next state $next")
        check(isValidTransition(state, next)) { "Invalid TLS state transition: $state -> $next" }
        state = next
    }

    /**
     * Decides whether [event] is permitted in the current state. Pure: does not transition and never inspects
     * handshake or alert bytes; the caller acts on the decision.
     */
    fun accept(event: TlsRecordEvent): TlsDecision {
        throwIfClosed("accept tls record event")
        val phase = state.toString()
        val acceptsHandshake = state == TlsState.AwaitClientHello
                || state == TlsState.AwaitClientFinished
                || state == TlsState.Established
        val acceptsCcs = state == TlsState.ProcessingClientHello
                || state == TlsState.AwaitClientFinished
        val acceptsApplicationData = state == TlsState.Established

        return when (event) {
            TlsRecordEvent.CompatibilityCcs ->
                if (acceptsCcs) TlsDecision.Ignore
                else TlsDecision.Reject(UnexpectMessageException("unexpected ChangeCipherSpec in state $phase"))

            is TlsRecordEvent.Empty -> when {
                event.type == TLS_CONTENT_TYPE_ALERT -> TlsDecision.Reject(DecodeErrorException("Malformed alert of length 0"))
                event.type == TLS_CONTENT_TYPE_APPLICATION_DATA_ && acceptsApplicationData -> TlsDecision.Ignore
                else -> TlsDecision.Reject(UnexpectedRecordException(event.type, phase))
            }

            is TlsRecordEvent.Content -> when (event.type) {
                TLS_CONTENT_TYPE_ALERT -> TlsDecision.ClientAlert
                TLS_CONTENT_TYPE_HANDSHAKE -> when {
                    acceptsHandshake -> TlsDecision.HandshakeFragment
                    else -> TlsDecision.Reject(UnexpectedRecordException(event.type, phase))
                }

                TLS_CONTENT_TYPE_APPLICATION_DATA_ -> when {
                    acceptsApplicationData -> TlsDecision.ApplicationData
                    acceptsHandshake ->
                        TlsDecision.Reject(
                            UnexpectedContentTypeException(
                                TLS_CONTENT_TYPE_HANDSHAKE,
                                event.type,
                                phase
                            )
                        )

                    else -> TlsDecision.Reject(UnexpectedRecordException(event.type, phase))
                }

                else -> TlsDecision.Reject(UnexpectedRecordException(event.type, phase))
            }
        }
    }

    fun throwIfClosed(operation: String) {
        if (closed) {
            throw IllegalStateException("$operation is not valid in state closed")
        }
    }

    fun close(error: Throwable?) {
        transitionTo(TlsState.Closed(error))
    }

    private fun isValidTransition(from: TlsState, to: TlsState): Boolean = when (to) {
        TlsState.AwaitClientHello -> false
        TlsState.ProcessingClientHello -> from == TlsState.AwaitClientHello
        TlsState.AwaitClientFinished -> from == TlsState.ProcessingClientHello
        TlsState.Established -> from == TlsState.AwaitClientFinished
        is TlsState.Closed -> true
    }
}