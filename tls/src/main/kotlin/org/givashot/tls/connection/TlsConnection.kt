package org.givashot.tls.connection

import org.givashot.tls.ServerProfile
import org.givashot.tls.constant.*
import org.givashot.tls.handshake.Tls13ServerHandshake
import org.givashot.tls.record.TlsRecordEvent
import org.givashot.tls.record.TlsRecordLayer
import org.givashot.tls.state.*
import java.security.GeneralSecurityException

/**
 * Coordinates the state machine, record layer and handshake. Owns no TLS state of its own:
 * lifecycle and KeyUpdate decisions live in TlsStateMachine, protection in TlsRecordLayer, secrets in Tls13ServerHandshake.
 */
class TlsConnection internal constructor(
    private val profile: ServerProfile,
    private val stateMachine: TlsStateMachine,
    private val recordLayer: TlsRecordLayer,
    private val handshake: Tls13ServerHandshake,
) {

    val state: TlsState get() = stateMachine.currentState()

    /**
     * Receive bytes from peer
     *
     * @param bytes from peer
     * @return processed tls client events
     */
    fun receive(bytes: ByteArray): List<TlsClientEvent> {
        stateMachine.throwIfClosed("receive data from client")
        recordLayer.feed(bytes)
        val events = ArrayList<TlsClientEvent>()
        // One record at a time: handling a record (Finished, KeyUpdate) may switch the read keys for the next one.
        while (true) {
            val clientEvent = try {
                val recordEvent = recordLayer.readNext() ?: break
                handleRecord(recordEvent)
            } catch (e: Exception) {
                val peerException = e.toPeerException()
                TlsClientEvent.ClientError(
                    peerException,
                    encodeAlert(TLS_ALERT_LEVEL_FATAL, peerException.replyAlert.code)
                )
            }
            if (clientEvent != null) {
                events += clientEvent
            }
            if (clientEvent is TlsClientEvent.ClientError || clientEvent is TlsClientEvent.ClientAlert) {
                break
            }
        }
        return events
    }

    private fun handleRecord(tlsRecordEvent: TlsRecordEvent): TlsClientEvent? {
        return when (val tlsDecision = stateMachine.accept(tlsRecordEvent)) {
            // CCS or empty application data, just ignore
            TlsDecision.Ignore -> null

            is TlsDecision.Reject -> TlsClientEvent.ClientError(
                tlsDecision.exception,
                encodeAlert(TLS_ALERT_LEVEL_FATAL, tlsDecision.exception.replyAlert.code)
            )

            is TlsDecision.HandshakeFragment ->
                handleHandshakeFragment((tlsRecordEvent as TlsRecordEvent.Content).payload)

            is TlsDecision.ApplicationData ->
                TlsClientEvent.ClientApplicationData((tlsRecordEvent as TlsRecordEvent.Content).payload)

            is TlsDecision.ClientAlert -> {
                val payload = (tlsRecordEvent as TlsRecordEvent.Content).payload
                if (payload.size != 2) throw DecodeErrorException("Malformed alert of length ${payload.size}")
                when (val alertCode = payload[1].toInt() and 0xFF) {
                    TlsAlert.CLOSE_NOTIFY.code -> TlsClientEvent.ClientAlert(
                        alertCode,
                        encodeAlert(TLS_ALERT_LEVEL_WARNING, TlsAlert.CLOSE_NOTIFY.code)
                    )

                    else -> TlsClientEvent.ClientAlert(alertCode)
                }
            }
        }
    }

    /**
     * execute tls command
     *
     * @param command you wanna execute
     * @return the tls record bytearrays you should reply to peer
     */
    fun execute(command: TlsCommand): List<ByteArray> {
        stateMachine.throwIfClosed("execute command ${command::class.simpleName}")
        return when (command) {
            is TlsCommand.SendServerFlight -> sendServerFlight(command)
            is TlsCommand.SendApplicationData -> sendApplicationData(command)
            is TlsCommand.SendKeyUpdate -> sendKeyUpdate(command)
            TlsCommand.Close -> {
                listOf(encodeAlert(TLS_ALERT_LEVEL_WARNING, TlsAlert.CLOSE_NOTIFY.code))
            }
        }
    }

    fun close(error: Throwable? = null) {
        stateMachine.close(error)
        recordLayer.reset()
        handshake.reset()
    }

    private fun sendServerFlight(command: TlsCommand.SendServerFlight): List<ByteArray> {
        if (state != TlsState.ProcessingClientHello) {
            throw TlsUsageInvalidStateException(
                "SendServerFlight",
                state.toString(),
                encodeAlert(TLS_ALERT_LEVEL_FATAL, TlsAlert.INTERNAL_ERROR.code)
            )
        }
        if (command.certificate.certificateChain.isEmpty()) {
            throw TlsUsageInvalidArgumentException(
                "Server certificate chain is empty",
                encodeAlert(TLS_ALERT_LEVEL_FATAL, TlsAlert.INTERNAL_ERROR.code)
            )
        }
        val recordLengths = command.recordLengths

        val flight = handshake.buildServerFlight(command.encryptedExtensions, command.certificate)
        val serverHelloRecord = recordLayer.encode(TLS_CONTENT_TYPE_HANDSHAKE, flight.serverHello)
        val handshakeTrafficSecrets = handshake.handshakeTrafficSecrets
        recordLayer.installWriteProtection(handshakeTrafficSecrets.serverTrafficKeys())
        recordLayer.installReadProtection(handshakeTrafficSecrets.clientTrafficKeys())
        val replyTlsRecords = arrayListOf(serverHelloRecord).apply {
            addAll(
                recordLayer.encode(
                    TLS_CONTENT_TYPE_HANDSHAKE,
                    flight.encodedHandshakes,
                    recordLengths
                )
            )
        }
        stateMachine.transitionTo(TlsState.AwaitClientFinished)
        return replyTlsRecords
    }

    private fun sendApplicationData(command: TlsCommand.SendApplicationData): List<ByteArray> {
        if (state != TlsState.Established) {
            throw TlsUsageInvalidStateException(
                "SendApplicationData",
                state.toString(),
                encodeAlert(TLS_ALERT_LEVEL_FATAL, TlsAlert.INTERNAL_ERROR.code)
            )
        }
        return if (command.recordLengths != null) {
            recordLayer.encode(TLS_CONTENT_TYPE_APPLICATION_DATA_, command.data, command.recordLengths)
        } else {
            listOf(
                recordLayer.encode(TLS_CONTENT_TYPE_APPLICATION_DATA_, command.data)
            )
        }
    }

    private fun sendKeyUpdate(command: TlsCommand.SendKeyUpdate): List<ByteArray> {
        if (!stateMachine.canSendKeyUpdate(command.requestPeer)) {
            throw TlsUsageInvalidStateException(
                "SendKeyUpdate",
                state.toString(),
                encodeAlert(TLS_ALERT_LEVEL_FATAL, TlsAlert.INTERNAL_ERROR.code)
            )
        }
        // The KeyUpdate itself is protected by the old write keys; only afterwards do the new ones take over.
        val keyUpdateTlsRecord = listOf(
            recordLayer.encode(
                TLS_CONTENT_TYPE_HANDSHAKE,
                handshake.encodeKeyUpdate(command.requestPeer)
            )
        )
        recordLayer.updateWriteKeys(handshake.nextTrafficKeys(recordLayer.writeKeys))
        stateMachine.onKeyUpdateSent(command.requestPeer)
        return keyUpdateTlsRecord
    }

    private fun handleHandshakeFragment(
        payload: ByteArray,
    ): TlsClientEvent? {
        return when (state) {
            TlsState.AwaitClientHello -> {
                val message = handshake.receiveClientHelloFragment(payload) ?: return null
                stateMachine.requireHandshakeType(message.type)
                val hello = handshake.onClientHello(message)
                stateMachine.transitionTo(TlsState.ProcessingClientHello)
                handshake.processClientHello()
                TlsClientEvent.ClientHello(hello)
            }

            TlsState.AwaitClientFinished -> {
                val message = handshake.receiveFragment(payload) ?: return null
                stateMachine.requireHandshakeType(message.type)
                handshake.onClientFinished(message)
                val applicationTrafficSecrets = handshake.applicationTrafficSecrets
                recordLayer.installReadProtection(applicationTrafficSecrets.clientTrafficKeys())
                recordLayer.installWriteProtection(applicationTrafficSecrets.serverTrafficKeys())
                stateMachine.transitionTo(TlsState.Established)
                TlsClientEvent.ClientFinished
            }

            TlsState.Established -> {
                val message = handshake.receiveFragment(payload) ?: return null
                stateMachine.requireHandshakeType(message.type)
                val keyUpdate = handshake.onKeyUpdate(message)
                val action = stateMachine.onKeyUpdateReceived(keyUpdate.updateRequested)
                recordLayer.updateReadKeys(handshake.nextTrafficKeys(recordLayer.readKeys))
                when (action) {
                    KeyUpdateAction.Reply -> {
                        val reply = recordLayer.encode(
                            TLS_CONTENT_TYPE_HANDSHAKE,
                            handshake.encodeKeyUpdate(false)
                        )
                        recordLayer.updateWriteKeys(handshake.nextTrafficKeys(recordLayer.writeKeys))
                        TlsClientEvent.ClientKeyUpdate(reply)
                    }

                    KeyUpdateAction.None -> TlsClientEvent.ClientKeyUpdate()
                }
            }

            else -> throw IllegalStateException("Handshake fragment accepted in state $state")
        }
    }

    private fun encodeAlert(level: Int, description: Int): ByteArray =
        recordLayer.encode(
            TLS_CONTENT_TYPE_ALERT,
            byteArrayOf(level.toByte(), description.toByte()),
        )

    private fun Exception.toPeerException(): TlsPeerProtocolException {
        return when (val ex = this@toPeerException) {
            is TlsPeerProtocolException -> ex
            is IllegalArgumentException, is IllegalStateException, is GeneralSecurityException ->
                UnexpectMessageException(ex.message.toString())

            else -> throw ex
        }
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
