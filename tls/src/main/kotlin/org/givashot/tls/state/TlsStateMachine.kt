package org.givashot.tls.state

import org.givashot.tls.connection.*
import org.givashot.tls.constant.*
import org.givashot.tls.record.TlsRecordEvent

internal class TlsStateMachine(initialState: TlsState = TlsState.AwaitClientHello) {

    private var state: TlsState = initialState

    /** True once we sent KeyUpdate(update_requested) and the peer has not yet answered with its own KeyUpdate. */
    private var awaitingPeerKeyUpdate = false

    val closed: Boolean get() = state is TlsState.Closed

    fun currentState(): TlsState = state

    fun transitionTo(next: TlsState) {
        throwIfClosed("transition to next state $next")
        check(isValidTransition(state, next)) { "Invalid TLS state transition: $state -> $next" }
        state = next
        if (next is TlsState.Closed) awaitingPeerKeyUpdate = false
    }

    /** Checks that a handshake message of [type] is the one the current state allows. Never touches the bytes. */
    fun requireHandshakeType(type: Int) {
        val expected = when (state) {
            TlsState.AwaitClientHello -> TLS_HANDSHAKE_CLIENT_HELLO_CONTENT_TYPE
            TlsState.AwaitClientFinished -> TLS_HANDSHAKE_FINISH_CONTENT_TYPE
            TlsState.Established -> TLS_HANDSHAKE_KEY_UPDATE_CONTENT_TYPE
            else -> throw IllegalStateException("Handshake message accepted in state $state")
        }
        if (type != expected) throw UnexpectedHandshakeTypeException(expected, type)
    }

    /** Sending is allowed once established; we do not stack a second request while one is still unanswered. */
    fun canSendKeyUpdate(requestPeer: Boolean): Boolean =
        state == TlsState.Established && !(requestPeer && awaitingPeerKeyUpdate)

    fun onKeyUpdateSent(requestPeer: Boolean) {
        check(canSendKeyUpdate(requestPeer)) { "KeyUpdate not allowed in state $state" }
        if (requestPeer) awaitingPeerKeyUpdate = true
    }

    /** Any KeyUpdate from the peer settles a pending request; [updateRequested] decides whether we must answer. */
    fun onKeyUpdateReceived(updateRequested: Boolean): KeyUpdateAction {
        check(state == TlsState.Established) { "KeyUpdate not allowed in state $state" }
        awaitingPeerKeyUpdate = false
        return if (updateRequested) KeyUpdateAction.Reply else KeyUpdateAction.None
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