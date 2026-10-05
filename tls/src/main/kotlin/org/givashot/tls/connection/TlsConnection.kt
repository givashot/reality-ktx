package org.givashot.tls.connection

import org.givashot.tls.ServerProfile
import org.givashot.tls.constant.TLS_CONTENT_TYPE_APPLICATION_DATA_
import org.givashot.tls.constant.TLS_CONTENT_TYPE_HANDSHAKE
import org.givashot.tls.handshake.Tls13ServerHandshake
import org.givashot.tls.record.TlsPlaintext
import org.givashot.tls.record.TlsRecordLayer
import org.givashot.tls.record.TlsRecordMessage
import org.givashot.tls.state.TlsState
import org.givashot.tls.state.TlsStateMachine
import org.givashot.tls.state.shutdown
import java.io.IOException
import java.security.GeneralSecurityException

/**
 * Coordinates the state machine, record layer and handshake. Owns no TLS state of its own:
 * lifecycle lives in TlsStateMachine, protection in TlsRecordLayer, secrets in Tls13ServerHandshake.
 */
class TlsConnection internal constructor(
    private val profile: ServerProfile,
    private val stateMachine: TlsStateMachine,
    private val recordLayer: TlsRecordLayer,
    private val handshake: Tls13ServerHandshake,
) {
    val state: TlsState get() = stateMachine.currentState()

    /** Plaintext bytes received before the read side switched to encryption; used to replay to a fallback target. */
    fun unauthenticatedInboundBytes(): ByteArray = recordLayer.plaintextInboundBytes()

    fun receive(bytes: ByteArray): TlsConnectionResult {
        usageErrorForShutdownState()?.let { return TlsConnectionResult.Err(it) }
        if (state == TlsState.ProcessingClientHello && bytes.isNotEmpty()) {
            return TlsConnectionResult.Err(TlsError.Usage.InputWhileAwaitingServerFlight)
        }
        try {
            recordLayer.feed(bytes)
        } catch (e: Exception) {
            return fail(toPeerError(e))
        }
        return drain(emptyList())
    }

    fun execute(command: TlsCommand): TlsConnectionResult = when (command) {
        is TlsCommand.SendServerFlight -> sendServerFlight(command)
        is TlsCommand.SendApplicationData -> sendApplicationData(command)
        TlsCommand.Close -> {
            close()
            TlsConnectionResult.Ok()
        }
    }

    fun close() {
        stateMachine.close()
        recordLayer.reset()
        handshake.reset()
    }

    private fun sendServerFlight(command: TlsCommand.SendServerFlight): TlsConnectionResult {
        usageErrorForShutdownState()?.let { return TlsConnectionResult.Err(it) }
        if (state != TlsState.ProcessingClientHello) {
            return TlsConnectionResult.Err(TlsError.Usage.InvalidState("SendServerFlight", state.toString()))
        }
        if (command.certificate.certificateChain.isEmpty()) {
            return TlsConnectionResult.Err(TlsError.Usage.InvalidArgument("Server certificate chain is empty"))
        }
        val recordLengths = command.recordLengths ?: profile.recordLengths

        val outbound = try {
            val flight = handshake.buildServerFlight(command.encryptedExtensions, command.certificate)
            val serverHelloRecords = recordLayer.encode(TLS_CONTENT_TYPE_HANDSHAKE, flight.serverHello, recordLengths)
            val handshakeTrafficSecrets = handshake.handshakeTrafficSecrets
            recordLayer.installWriteProtection(handshakeTrafficSecrets.serverTrafficKeys())
            recordLayer.installReadProtection(handshakeTrafficSecrets.clientTrafficKeys())
            serverHelloRecords + recordLayer.encode(TLS_CONTENT_TYPE_HANDSHAKE, flight.encodedHandshakes, recordLengths)
        } catch (e: Exception) {
            return fail(toPeerError(e))
        }
        stateMachine.transitionTo(TlsState.AwaitClientHandshake)
        stateMachine.transitionTo(TlsState.AwaitClientFinished)
        return drain(outbound)
    }

    private fun sendApplicationData(command: TlsCommand.SendApplicationData): TlsConnectionResult {
        usageErrorForShutdownState()?.let { return TlsConnectionResult.Err(it) }
        if (state != TlsState.Established) {
            return TlsConnectionResult.Err(TlsError.Usage.InvalidState("SendApplicationData", state.toString()))
        }
        val records = try {
            recordLayer.encode(
                TLS_CONTENT_TYPE_APPLICATION_DATA_,
                command.data,
                command.recordLengths ?: profile.recordLengths,
            )
        } catch (e: Exception) {
            return fail(toPeerError(e))
        }
        return TlsConnectionResult.Ok(outbound = records)
    }

    /** Processes queued records until one needs the application (ClientHello) or the queue is empty. */
    private fun drain(outbound: List<ByteArray>): TlsConnectionResult {
        val events = ArrayList<TlsEvent>()
        while (state != TlsState.ProcessingClientHello && !state.shutdown()) {
            val record = recordLayer.nextRecord() ?: break
            val error = try {
                handleRecord(record, events)
            } catch (e: Exception) {
                toPeerError(e)
            }
            if (error != null) return fail(error)
        }
        return TlsConnectionResult.Ok(events, outbound)
    }

    private fun handleRecord(record: TlsRecordMessage, events: MutableList<TlsEvent>): TlsError.Peer? {
        if (recordLayer.isChangeCipherSpec(record)) return handleChangeCipherSpec(record)

        when (state) {
            TlsState.AwaitClientHello -> {
                expectContentType(record.contentType, TLS_CONTENT_TYPE_HANDSHAKE, "AwaitClientHello")?.let { return it }
                val hello = handshake.onClientHelloFragment(record.payload) ?: return null
                stateMachine.transitionTo(TlsState.ProcessingClientHello)
                handshake.processClientHello()
                events += TlsEvent.ClientHello(hello)
            }

            TlsState.AwaitClientHandshake, TlsState.AwaitClientFinished -> {
                expectContentType(record.contentType, TLS_CONTENT_TYPE_APPLICATION_DATA_, "AwaitClientFinished")
                    ?.let { return it }
                val plaintext = recordLayer.decode(record)
                expectContentType(plaintext.contentType, TLS_CONTENT_TYPE_HANDSHAKE, "AwaitClientFinished")
                    ?.let { return it }
                if (!handshake.onClientFinishedFragment(plaintext.payload)) return null
                val applicationTrafficSecrets = handshake.applicationTrafficSecrets
                recordLayer.installReadProtection(applicationTrafficSecrets.clientTrafficKeys())
                recordLayer.installWriteProtection(applicationTrafficSecrets.serverTrafficKeys())
                stateMachine.transitionTo(TlsState.Established)
                events += TlsEvent.ClientFinished
            }

            TlsState.Established -> {
                expectContentType(record.contentType, TLS_CONTENT_TYPE_APPLICATION_DATA_, "Established")?.let { return it }
                val plaintext: TlsPlaintext = recordLayer.decode(record)
                expectContentType(plaintext.contentType, TLS_CONTENT_TYPE_APPLICATION_DATA_, "Established")
                    ?.let { return it }
                events += TlsEvent.ClientApplicationData(plaintext.payload)
            }

            TlsState.ProcessingClientHello, is TlsState.Failed, TlsState.Closed ->
                error("Record handled in state " + state)
        }
        return null
    }

    /** A compatibility CCS is legal only between ClientHello and client Finished (RFC 8446 appendix D.4). */
    private fun handleChangeCipherSpec(record: TlsRecordMessage): TlsError.Peer? {
        val allowed = state == TlsState.AwaitClientHandshake || state == TlsState.AwaitClientFinished
        if (!allowed) {
            return TlsError.Peer.InvalidChangeCipherSpec("unexpected ChangeCipherSpec in state " + state)
        }
        if (!recordLayer.dropChangeCipherSpec(record)) {
            return TlsError.Peer.InvalidChangeCipherSpec("malformed or repeated ChangeCipherSpec")
        }
        return null
    }

    private fun expectContentType(actual: Int, expected: Int, phase: String): TlsError.Peer? =
        if (actual == expected) null else TlsError.Peer.UnexpectedContentType(expected, actual, phase)

    private fun usageErrorForShutdownState(): TlsError.Usage? = when (val current = state) {
        is TlsState.Closed -> TlsError.Usage.ConnectionClosed
        is TlsState.Failed -> TlsError.Usage.ConnectionFailed(current.error)
        else -> null
    }

    private fun fail(error: TlsError.Peer): TlsConnectionResult.Err {
        stateMachine.fail(error)
        recordLayer.reset()
        handshake.reset()
        return TlsConnectionResult.Err(error)
    }

    private fun toPeerError(e: Exception): TlsError.Peer = when (e) {
        is TlsProtocolException -> e.error
        is IllegalArgumentException, is IllegalStateException, is GeneralSecurityException, is IOException ->
            TlsError.Peer.ProcessingFailure(e)
        else -> throw e
    }

    companion object {
        fun create(profile: ServerProfile): TlsConnection = TlsConnection(
            profile = profile,
            stateMachine = TlsStateMachine(),
            recordLayer = TlsRecordLayer(profile.maxRecordSize),
            handshake = Tls13ServerHandshake(profile),
        )
    }
}
