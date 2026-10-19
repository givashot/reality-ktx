package org.givashot.tls.connection

import org.givashot.tls.ServerProfile
import org.givashot.tls.constant.*
import org.givashot.tls.handshake.Tls13ServerHandshakeCodec
import org.givashot.tls.record.TlsRecordEvent
import org.givashot.tls.record.TlsRecordLayer
import org.givashot.tls.state.TlsAlert
import org.givashot.tls.state.TlsDecision
import org.givashot.tls.state.TlsState
import org.givashot.tls.state.TlsStateMachine
import java.security.GeneralSecurityException

/**
 * Coordinates the state machine, record layer and handshake. Owns no TLS state of its own:
 * lifecycle lives in TlsStateMachine, protection in TlsRecordLayer, secrets in Tls13ServerHandshake.
 */
class TlsConnection internal constructor(
    private val profile: ServerProfile,
    private val stateMachine: TlsStateMachine,
    private val recordLayer: TlsRecordLayer,
    private val handshakeCodec: Tls13ServerHandshakeCodec,
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
        var breakAfterEvent = false
        return recordLayer.feed(bytes).mapNotNull { tlsRecordEvent ->
            if (breakAfterEvent) return@mapNotNull null
            var tlsClientEvent: TlsClientEvent? = null
            var peerProtocolException: TlsPeerProtocolException? = null
            try {
                when (val tlsDecision = stateMachine.accept(tlsRecordEvent)) {
                    TlsDecision.Ignore -> {
                        // CCS or empty application data, just ignore
                    }

                    is TlsDecision.Reject -> {
                        breakAfterEvent = true
                        tlsClientEvent = TlsClientEvent.ClientError(
                            tlsDecision.exception,
                            encodeAlert(TLS_ALERT_LEVEL_FATAL, tlsDecision.exception.replyAlert.code)
                        )
                    }

                    is TlsDecision.HandshakeFragment -> {
                        tlsClientEvent = handleHandshakeFragment((tlsRecordEvent as TlsRecordEvent.Content).payload)
                    }

                    is TlsDecision.ApplicationData -> {
                        tlsClientEvent =
                            TlsClientEvent.ClientApplicationData((tlsRecordEvent as TlsRecordEvent.Content).payload)
                    }

                    is TlsDecision.ClientAlert -> {
                        val payload = (tlsRecordEvent as TlsRecordEvent.Content).payload
                        if (payload.size == 2) {
                            tlsClientEvent = when (val alertCode = payload[1].toInt() and 0xFF) {
                                TlsAlert.CLOSE_NOTIFY.code -> {
                                    TlsClientEvent.ClientAlert(
                                        alertCode,
                                        encodeAlert(TLS_ALERT_LEVEL_WARNING, TlsAlert.CLOSE_NOTIFY.code)
                                    )
                                }

                                else -> {
                                    TlsClientEvent.ClientAlert(alertCode)
                                }
                            }
                            // break after event
                            breakAfterEvent = true
                        } else {
                            peerProtocolException = DecodeErrorException("Malformed alert of length ${payload.size}")
                        }
                    }
                }
            } catch (e: Exception) {
                peerProtocolException = e.toPeerException()
            }
            if (peerProtocolException != null) {
                tlsClientEvent = TlsClientEvent.ClientError(
                    peerProtocolException,
                    encodeAlert(TLS_ALERT_LEVEL_FATAL, peerProtocolException.replyAlert.code)
                )
                // break after event
                breakAfterEvent = true
            }
            return@mapNotNull tlsClientEvent
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
        handshakeCodec.reset()
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

        val flight = handshakeCodec.buildServerFlight(command.encryptedExtensions, command.certificate)
        val serverHelloRecord = recordLayer.encode(TLS_CONTENT_TYPE_HANDSHAKE, flight.serverHello)
        val handshakeTrafficSecrets = handshakeCodec.handshakeTrafficSecrets
        recordLayer.installWriteProtection(handshakeTrafficSecrets.serverTrafficKeys())
        recordLayer.installReadProtection(handshakeTrafficSecrets.clientTrafficKeys())
        val replyTlsRecords = arrayListOf(serverHelloRecord).apply {
            addAll(recordLayer.encode(TLS_CONTENT_TYPE_HANDSHAKE, flight.encodedHandshakes, recordLengths))
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
        if (state != TlsState.Established) {
            throw TlsUsageInvalidStateException(
                "SendKeyUpdate",
                state.toString(),
                encodeAlert(TLS_ALERT_LEVEL_FATAL, TlsAlert.INTERNAL_ERROR.code)
            )
        }
        val message = handshakeCodec.encodeKeyUpdate(command.requestPeer)
        val keyUpdateTlsRecord = listOf(recordLayer.encode(
            TLS_CONTENT_TYPE_HANDSHAKE,
            message
        ))
        recordLayer.updateWriteKeys()
        return keyUpdateTlsRecord
    }

    private fun handleHandshakeFragment(
        payload: ByteArray,
    ): TlsClientEvent? {
        return when (state) {
            TlsState.AwaitClientHello -> {
                handshakeCodec.onClientHelloFragment(payload)?.let { helloWrapper ->
                    stateMachine.transitionTo(TlsState.ProcessingClientHello)
                    handshakeCodec.processClientHello()
                    TlsClientEvent.ClientHello(helloWrapper)
                }
            }

            TlsState.AwaitClientFinished -> {
                if (!handshakeCodec.onClientFinishedFragment(payload)) {
                    null
                } else {
                    val applicationTrafficSecrets = handshakeCodec.applicationTrafficSecrets
                    recordLayer.installReadProtection(applicationTrafficSecrets.clientTrafficKeys())
                    recordLayer.installWriteProtection(applicationTrafficSecrets.serverTrafficKeys())
                    stateMachine.transitionTo(TlsState.Established)
                    TlsClientEvent.ClientFinished
                }
            }

            TlsState.Established -> {
                val keyUpdate = handshakeCodec.handleKeyUpdate(payload) ?: return null
                recordLayer.updateReadKeys()
                if (keyUpdate.updateRequested) {
                    val reply = recordLayer.encode(
                        TLS_CONTENT_TYPE_HANDSHAKE,
                        handshakeCodec.encodeKeyUpdate(requestPeer = false)
                    )
                    recordLayer.updateWriteKeys()
                    TlsClientEvent.ClientKeyUpdate(reply)
                } else {
                    TlsClientEvent.ClientKeyUpdate()
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
            handshakeCodec = Tls13ServerHandshakeCodec(profile),
        )
    }
}
