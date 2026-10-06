package org.givashot.tls

import org.givashot.tls.connection.TlsError
import org.givashot.tls.constant.TLS_CONTENT_TYPE_ALERT
import org.givashot.tls.constant.TLS_CONTENT_TYPE_APPLICATION_DATA_
import org.givashot.tls.constant.TLS_CONTENT_TYPE_HANDSHAKE
import org.givashot.tls.record.TlsRecordEvent
import org.givashot.tls.state.TlsAlert
import org.givashot.tls.state.TlsDecision
import org.givashot.tls.state.TlsState
import org.givashot.tls.state.TlsStateMachine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class TlsStateMachineTest {
    private val error = TlsError.Peer.ClientFinishedVerificationFailed

    @Test
    fun `starts waiting for client hello`() {
        assertEquals(TlsState.AwaitClientHello, TlsStateMachine().currentState())
    }

    @Test
    fun `walks the happy path in order`() {
        val machine = TlsStateMachine()
        for (next in listOf(
            TlsState.ProcessingClientHello,
            TlsState.AwaitClientHandshake,
            TlsState.AwaitClientFinished,
            TlsState.Established,
            TlsState.Closed,
        )) {
            machine.transitionTo(next)
            assertEquals(next, machine.currentState())
        }
    }

    @Test
    fun `rejects skipped and backward transitions`() {
        val machine = TlsStateMachine()
        assertFailsWith<IllegalStateException> { machine.transitionTo(TlsState.Established) }
        assertFailsWith<IllegalStateException> { machine.transitionTo(TlsState.AwaitClientFinished) }
        machine.transitionTo(TlsState.ProcessingClientHello)
        assertFailsWith<IllegalStateException> { machine.transitionTo(TlsState.AwaitClientHello) }
        assertFailsWith<IllegalStateException> { machine.transitionTo(TlsState.ProcessingClientHello) }
    }

    @Test
    fun `fail records alert and error then ignores further failures`() {
        val machine = TlsStateMachine()
        machine.fail(error)
        val failed = assertIs<TlsState.Failed>(machine.currentState())
        assertEquals(error, failed.error)
        assertEquals(TlsAlert.DECRYPT_ERROR, failed.alert)

        machine.fail(TlsError.Peer.NegotiationFailed("again"))
        assertEquals(failed, machine.currentState())
    }

    @Test
    fun `close is idempotent and terminal`() {
        val machine = TlsStateMachine()
        machine.close()
        machine.close()
        assertEquals(TlsState.Closed, machine.currentState())
        machine.fail(error)
        assertEquals(TlsState.Closed, machine.currentState())
        assertFailsWith<IllegalStateException> { machine.transitionTo(TlsState.ProcessingClientHello) }
    }

    @Test
    fun `failed state can be closed`() {
        val machine = TlsStateMachine()
        machine.fail(error)
        machine.close()
        assertEquals(TlsState.Closed, machine.currentState())
    }

    private fun decision(state: TlsState, event: TlsRecordEvent): TlsDecision {
        val machine = TlsStateMachine()
        listOf(
            TlsState.ProcessingClientHello,
            TlsState.AwaitClientHandshake,
            TlsState.AwaitClientFinished,
            TlsState.Established,
        ).forEach { if (machine.currentState() != state) machine.transitionTo(it) }
        return machine.accept(event)
    }

    private fun content(type: Int) = TlsRecordEvent.Content(type, byteArrayOf(1, 2))

    @Test
    fun `await client hello accepts only handshake and alert`() {
        val s = TlsState.AwaitClientHello
        assertIs<TlsDecision.HandshakeFragment>(decision(s, content(TLS_CONTENT_TYPE_HANDSHAKE)))
        assertIs<TlsDecision.Alert>(decision(s, content(TLS_CONTENT_TYPE_ALERT)))
        assertIs<TlsDecision.Reject>(decision(s, TlsRecordEvent.CompatibilityCcs))
        assertIs<TlsDecision.Reject>(decision(s, content(TLS_CONTENT_TYPE_APPLICATION_DATA_)))
        assertIs<TlsDecision.Reject>(decision(s, TlsRecordEvent.Empty(TLS_CONTENT_TYPE_HANDSHAKE)))
    }

    @Test
    fun `ccs is allowed throughout the compatibility window only`() {
        assertEquals(TlsDecision.Ignore, decision(TlsState.ProcessingClientHello, TlsRecordEvent.CompatibilityCcs))
        assertEquals(TlsDecision.Ignore, decision(TlsState.AwaitClientHandshake, TlsRecordEvent.CompatibilityCcs))
        assertEquals(TlsDecision.Ignore, decision(TlsState.AwaitClientFinished, TlsRecordEvent.CompatibilityCcs))
        assertIs<TlsDecision.Reject>(decision(TlsState.Established, TlsRecordEvent.CompatibilityCcs))
    }

    @Test
    fun `processing client hello rejects handshake and application data`() {
        val s = TlsState.ProcessingClientHello
        assertIs<TlsDecision.Reject>(decision(s, content(TLS_CONTENT_TYPE_HANDSHAKE)))
        assertIs<TlsDecision.Reject>(decision(s, content(TLS_CONTENT_TYPE_APPLICATION_DATA_)))
    }

    @Test
    fun `await client finished accepts handshake but not application data`() {
        val s = TlsState.AwaitClientFinished
        assertIs<TlsDecision.HandshakeFragment>(decision(s, content(TLS_CONTENT_TYPE_HANDSHAKE)))
        assertIs<TlsDecision.Reject>(decision(s, content(TLS_CONTENT_TYPE_APPLICATION_DATA_)))
    }

    @Test
    fun `established accepts application data and empty application data only`() {
        val s = TlsState.Established
        assertIs<TlsDecision.ApplicationData>(decision(s, content(TLS_CONTENT_TYPE_APPLICATION_DATA_)))
        assertEquals(TlsDecision.Ignore, decision(s, TlsRecordEvent.Empty(TLS_CONTENT_TYPE_APPLICATION_DATA_)))
        assertIs<TlsDecision.Reject>(decision(s, content(TLS_CONTENT_TYPE_HANDSHAKE)))
        assertIs<TlsDecision.Reject>(decision(s, TlsRecordEvent.Empty(TLS_CONTENT_TYPE_HANDSHAKE)))
        assertEquals(
            TlsDecision.Reject(TlsError.Peer.MalformedAlert(0)),
            decision(s, TlsRecordEvent.Empty(TLS_CONTENT_TYPE_ALERT)),
        )
    }
}