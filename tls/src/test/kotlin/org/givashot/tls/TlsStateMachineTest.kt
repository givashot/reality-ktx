package org.givashot.tls

import org.givashot.tls.connection.TlsError
import org.givashot.tls.state.TlsAlert
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
}
