package org.givashot.tls.connection

import org.givashot.tls.ServerProfile
import org.givashot.tls.constant.TLS_CONTENT_TYPE_ALERT
import org.givashot.tls.constant.TLS_CONTENT_TYPE_APPLICATION_DATA_
import org.givashot.tls.constant.TLS_CONTENT_TYPE_HANDSHAKE
import org.givashot.tls.constant.TLS_ALERT_LEVEL_FATAL
import org.givashot.tls.constant.TLS_ALERT_LEVEL_WARNING
import org.givashot.tls.constant.TLS_HANDSHAKE_KEY_UPDATE_CONTENT_TYPE
import org.givashot.tls.handshake.HandshakeMessageDecoder
import org.givashot.tls.handshake.Tls13ServerHandshake
import org.givashot.tls.record.TlsRecordLayer
import org.givashot.tls.state.TlsAlert
import org.givashot.tls.state.TlsDecision
import org.givashot.tls.state.TlsState
import org.givashot.tls.state.TlsStateMachine
import org.givashot.tls.state.shutdown
import org.givashot.tls.crypto.tlsHandshakeMessage
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
    private val postHandshakeDecoder = HandshakeMessageDecoder()
    private var closeNotifySent = false

    val state: TlsState get() = stateMachine.currentState()

    /** Plaintext bytes received before the read side switched to encryption; used to replay to a fallback target. */
    fun unauthenticatedInboundBytes(): ByteArray = recordLayer.plaintextInboundBytes()

    fun receive(bytes: ByteArray): TlsConnectionResult {
        usageErrorForShutdownState()?.let { return TlsConnectionResult.Err(it) }
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
        is TlsCommand.SendKeyUpdate -> sendKeyUpdate(command)
        TlsCommand.Close -> {
            sendCloseNotify()
        }
    }

    fun close() {
        stateMachine.close()
        recordLayer.reset()
        handshake.reset()
        postHandshakeDecoder.reset()
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

    private fun sendKeyUpdate(command: TlsCommand.SendKeyUpdate): TlsConnectionResult {
        usageErrorForShutdownState()?.let { return TlsConnectionResult.Err(it) }
        if (state != TlsState.Established) {
            return TlsConnectionResult.Err(TlsError.Usage.InvalidState("SendKeyUpdate", state.toString()))
        }
        val outbound = try {
            val message = encodeKeyUpdate(command.requestPeer)
            val records = recordLayer.encode(
                TLS_CONTENT_TYPE_HANDSHAKE,
                message,
                profile.recordLengths,
            )
            recordLayer.updateWriteKeys()
            records
        } catch (e: Exception) {
            return fail(toPeerError(e))
        }
        return TlsConnectionResult.Ok(outbound = outbound)
    }

    private fun sendCloseNotify(): TlsConnectionResult {
        if (state.shutdown()) {
            close()
            return TlsConnectionResult.Ok()
        }
        val outbound = try {
            encodeAlert(TLS_ALERT_LEVEL_WARNING, TlsAlert.CLOSE_NOTIFY_CODE)
        } catch (e: Exception) {
            return fail(toPeerError(e))
        }
        closeNotifySent = true
        close()
        return TlsConnectionResult.Ok(outbound = outbound)
    }

    /** Feeds queued record events through the state machine and acts on its decisions until the queue is empty. */
    private fun drain(outbound: List<ByteArray>): TlsConnectionResult {
        val events = ArrayList<TlsEvent>()
        val outboundRecords = ArrayList(outbound)
        while (!state.shutdown()) {
            val error = try {
                val event = recordLayer.nextEvent() ?: break
                handleDecision(stateMachine.accept(event), events, outboundRecords)
            } catch (e: Exception) {
                toPeerError(e)
            }
            if (error != null) return fail(error, outboundRecords)
        }
        return TlsConnectionResult.Ok(events, outboundRecords)
    }

    private fun handleDecision(
        decision: TlsDecision,
        events: MutableList<TlsEvent>,
        outbound: MutableList<ByteArray>,
    ): TlsError.Peer? {
        when (decision) {
            TlsDecision.Ignore -> Unit
            is TlsDecision.Reject -> return decision.error
            is TlsDecision.ApplicationData -> events += TlsEvent.ClientApplicationData(decision.payload)
            is TlsDecision.HandshakeFragment -> handleHandshakeFragment(decision.payload, events, outbound)
            is TlsDecision.Alert -> return handleAlert(decision.payload, events, outbound)
        }
        return null
    }

    private fun handleHandshakeFragment(
        payload: ByteArray,
        events: MutableList<TlsEvent>,
        outbound: MutableList<ByteArray>,
    ) {
        when (state) {
            TlsState.AwaitClientHello -> {
                val hello = handshake.onClientHelloFragment(payload) ?: return
                stateMachine.transitionTo(TlsState.ProcessingClientHello)
                handshake.processClientHello()
                events += TlsEvent.ClientHello(hello)
            }

            TlsState.AwaitClientHandshake, TlsState.AwaitClientFinished -> {
                if (!handshake.onClientFinishedFragment(payload)) return
                val applicationTrafficSecrets = handshake.applicationTrafficSecrets
                recordLayer.installReadProtection(applicationTrafficSecrets.clientTrafficKeys())
                recordLayer.installWriteProtection(applicationTrafficSecrets.serverTrafficKeys())
                stateMachine.transitionTo(TlsState.Established)
                events += TlsEvent.ClientFinished
            }

            TlsState.Established -> handlePostHandshakeFragment(payload, outbound)

            else -> error("Handshake fragment accepted in state $state")
        }
    }

    private fun handlePostHandshakeFragment(payload: ByteArray, outbound: MutableList<ByteArray>) {
        val messages = try {
            postHandshakeDecoder.feed(payload)
        } catch (_: IllegalArgumentException) {
            throw TlsProtocolException(
                TlsError.Peer.MalformedKeyUpdate("message exceeds the maximum size"),
            )
        }
        if (messages.size > 1 || (messages.size == 1 && postHandshakeDecoder.bufferedByteCount != 0)) {
            throw TlsProtocolException(TlsError.Peer.UnexpectedExtraHandshakeData("KeyUpdate"))
        }
        messages.forEach { message ->
            if (message.type != TLS_HANDSHAKE_KEY_UPDATE_CONTENT_TYPE) {
                throw TlsProtocolException(
                    TlsError.Peer.UnexpectedHandshakeType(TLS_HANDSHAKE_KEY_UPDATE_CONTENT_TYPE, message.type),
                )
            }
            if (message.body.size != 1) {
                throw TlsProtocolException(
                    TlsError.Peer.MalformedKeyUpdate("body must contain exactly one byte"),
                )
            }
            val updateRequested = when (message.body[0].toInt() and 0xFF) {
                0 -> false
                1 -> true
                else -> throw TlsProtocolException(
                    TlsError.Peer.InvalidKeyUpdateRequest,
                )
            }
            recordLayer.updateReadKeys()
            if (updateRequested) {
                outbound += recordLayer.encode(
                    TLS_CONTENT_TYPE_HANDSHAKE,
                    encodeKeyUpdate(requestPeer = false),
                    profile.recordLengths,
                )
                recordLayer.updateWriteKeys()
            }
        }
    }

    /** RFC 8446 section 6: exactly one 2-byte alert per record; close_notify and user_canceled are not fatal to us. */
    private fun handleAlert(
        payload: ByteArray,
        events: MutableList<TlsEvent>,
        outbound: MutableList<ByteArray>,
    ): TlsError.Peer? {
        if (payload.size != 2) return TlsError.Peer.MalformedAlert(payload.size)
        return when (val code = payload[1].toInt() and 0xFF) {
            TlsAlert.CLOSE_NOTIFY_CODE -> {
                if (!closeNotifySent) {
                    outbound += encodeAlert(TLS_ALERT_LEVEL_WARNING, TlsAlert.CLOSE_NOTIFY_CODE)
                    closeNotifySent = true
                }
                events += TlsEvent.ClientCloseNotify
                close()
                null
            }

            TlsAlert.USER_CANCELED_CODE -> null
            else -> TlsError.Peer.AlertReceived(code)
        }
    }

    private fun encodeAlert(level: Int, description: Int): List<ByteArray> =
        recordLayer.encode(
            TLS_CONTENT_TYPE_ALERT,
            byteArrayOf(level.toByte(), description.toByte()),
            profile.recordLengths,
        )

    private fun encodeKeyUpdate(requestPeer: Boolean): ByteArray =
        tlsHandshakeMessage(
            TLS_HANDSHAKE_KEY_UPDATE_CONTENT_TYPE,
            byteArrayOf(if (requestPeer) 1 else 0),
        )

    private fun usageErrorForShutdownState(): TlsError.Usage? = when (val current = state) {
        is TlsState.Closed -> TlsError.Usage.ConnectionClosed
        is TlsState.Failed -> TlsError.Usage.ConnectionFailed(current.error)
        else -> null
    }

    private fun fail(
        error: TlsError.Peer,
        alreadyOutbound: List<ByteArray> = emptyList(),
    ): TlsConnectionResult.Err {
        val outbound = ArrayList(alreadyOutbound)
        TlsAlert.forError(error)?.let { alert ->
            outbound += encodeAlert(TLS_ALERT_LEVEL_FATAL, alert.code)
        }
        stateMachine.fail(error)
        recordLayer.reset()
        handshake.reset()
        postHandshakeDecoder.reset()
        return TlsConnectionResult.Err(error, outbound)
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
