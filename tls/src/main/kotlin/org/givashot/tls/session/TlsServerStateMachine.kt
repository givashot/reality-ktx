package org.givashot.tls.session

import org.bouncycastle.tls.ClientHello
import org.givashot.tls.ServerProfile
import org.givashot.tls.constant.*
import org.givashot.tls.crypto.KeySchedule
import org.givashot.tls.handshake.*
import org.givashot.tls.record.TlsRecordLayer
import org.givashot.tls.record.TlsRecordMessage
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.util.*

class TlsServerStateMachine(private val profile: ServerProfile) {
    private val recordLayer = TlsRecordLayer(profile.maxRecordSize)
    private val serverHandshake = Tls13ServerHandshake()
    private val plaintextHandshakeDecoder = HandshakeMessageDecoder(TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH)
    private val encryptedHandshakeDecoder = HandshakeMessageDecoder()
    private val pendingRecords = ArrayDeque<TlsRecordMessage>()
    private var state: TlsState = TlsState.AwaitClientHello(plaintextHandshakeDecoder)

    val phase: TlsPhase get() = state.phase

    fun rawClientHelloBytes(): ByteArray? {
        return when (val current = state) {
            is TlsState.AwaitServerFlight -> current.clientHello.rawRecordBytes
            else -> null
        }
    }

    fun processClientData(bytes: ByteArray): TlsResult<List<ClientTlsEvent>> {
        when (state) {
            is TlsState.Closed -> return TlsResult.Err(TlsError.Usage.ConnectionClosed)
            is TlsState.Failed -> return TlsResult.Err(
                TlsError.Usage.ConnectionFailed((state as TlsState.Failed).error),
            )
            is TlsState.AwaitServerFlight -> if (bytes.isNotEmpty()) {
                return TlsResult.Err(TlsError.Usage.InputWhileAwaitingServerFlight)
            }
            else -> Unit
        }

        val records: List<TlsRecordMessage> = if (bytes.isEmpty()) emptyList() else when (val result = guard { recordLayer.feed(bytes) }) {
            is TlsResult.Err -> return failPeer(result.error as? TlsError.Peer ?: TlsError.Peer.ProcessingFailure(IllegalStateException(result.error.description)))
            is TlsResult.Ok -> result.value
        }
        pendingRecords.addAll(records)

        val events = ArrayList<ClientTlsEvent>()
        while (pendingRecords.isNotEmpty() && state !is TlsState.AwaitServerFlight) {
            val record = pendingRecords.removeFirst()
            val transition = when (val current = state) {
                is TlsState.AwaitClientHello -> onAwaitClientHello(current, record)
                is TlsState.AwaitClientFinished -> onAwaitClientFinished(current, record)
                is TlsState.Established -> onEstablished(record)
                is TlsState.AwaitServerFlight -> TlsResult.Err(TlsError.Usage.InputWhileAwaitingServerFlight)
                is TlsState.Failed -> TlsResult.Err(TlsError.Usage.ConnectionFailed(current.error))
                is TlsState.Closed -> TlsResult.Err(TlsError.Usage.ConnectionClosed)
            }
            when (transition) {
                is TlsResult.Ok -> {
                    state = transition.value.next
                    events += transition.value.events
                }
                is TlsResult.Err -> {
                    val peer = transition.error as? TlsError.Peer
                    if (peer != null) return failPeer(peer)
                    return TlsResult.Err(transition.error)
                }
            }
        }
        return TlsResult.Ok(events)
    }

    fun buildServerFlight(
        encryptedExtensions: EncryptedExtensionsData,
        certificate: CertificateData,
    ): TlsResult<List<ByteArray>> = buildServerFlight(encryptedExtensions, certificate, profile.recordLengths)

    fun buildServerFlight(
        encryptedExtensions: EncryptedExtensionsData,
        certificate: CertificateData,
        recordLengths: List<Int>,
    ): TlsResult<List<ByteArray>> {
        when (val current = state) {
            is TlsState.AwaitServerFlight -> Unit
            is TlsState.Closed -> return TlsResult.Err(TlsError.Usage.ConnectionClosed)
            is TlsState.Failed -> return TlsResult.Err(TlsError.Usage.ConnectionFailed(current.error))
            else -> return TlsResult.Err(TlsError.Usage.InvalidState("buildServerFlight", phase.name))
        }
        if (certificate.certificateChain.isEmpty()) {
            return TlsResult.Err(TlsError.Usage.InvalidArgument("Server certificate chain is empty"))
        }

        val currentClientHello = (state as TlsState.AwaitServerFlight).clientHello
        val result = when (val built = guard {
            serverHandshake.buildFlight(
                clientHello = currentClientHello,
                encryptedExtensions = encryptedExtensions,
                certificate = certificate,
                profile = profile.copy(recordLengths = recordLengths),
            )
        }) {
            is TlsResult.Err -> return failPeerOrUsage(built.error)
            is TlsResult.Ok -> built.value
        }

        val serverHelloRecord = recordLayer.encode(TLS_HANDSHAKE_CONTENT_TYPE, result.serverHello, recordLengths).single()
        recordLayer.installHandshakeKeys(result.handshakeSecrets)
        val encrypted = recordLayer.encode(TLS_HANDSHAKE_CONTENT_TYPE, result.encryptedHandshake, recordLengths)
        state = TlsState.AwaitClientFinished(
            handshakeSecrets = result.handshakeSecrets,
            applicationSecrets = result.applicationSecrets,
            transcriptHash = result.transcriptHash,
            handshakeDecoder = HandshakeMessageDecoder(),
        )
        return TlsResult.Ok(listOf(serverHelloRecord) + encrypted)
    }

    fun encryptServerApplicationData(plaintext: ByteArray): TlsResult<List<ByteArray>> =
        encryptServerApplicationData(plaintext, profile.recordLengths)

    fun encryptServerApplicationData(
        plaintext: ByteArray,
        recordLengths: List<Int>,
    ): TlsResult<List<ByteArray>> {
        if (state !is TlsState.Established) {
            return TlsResult.Err(TlsError.Usage.InvalidState("encryptServerApplicationData", phase.name))
        }
        val result = when (val encrypted = guard { recordLayer.encode(TLS_APPLICATION_DATA_CONTENT_TYPE, plaintext, recordLengths) }) {
            is TlsResult.Err -> return failPeerOrUsage(encrypted.error)
            is TlsResult.Ok -> encrypted.value
        }
        return TlsResult.Ok(result)
    }

    fun close() {
        state = TlsState.Closed
        pendingRecords.clear()
        recordLayer.reset()
        plaintextHandshakeDecoder.reset()
        encryptedHandshakeDecoder.reset()
    }

    private class Transition(val next: TlsState, val events: List<ClientTlsEvent> = emptyList())

    private fun onAwaitClientHello(s: TlsState.AwaitClientHello, r: TlsRecordMessage): TlsResult<Transition> {
        if (r.contentType != TLS_HANDSHAKE_CONTENT_TYPE) {
            return TlsResult.Err(
                TlsError.Peer.UnexpectedContentType(
                    expected = TLS_HANDSHAKE_CONTENT_TYPE,
                    actual = r.contentType,
                    phase = "EXPECT_CLIENT_HELLO",
                ),
            )
        }
        val messages = when (val result = guard { s.handshakeDecoder.feed(r.payload) }) {
            is TlsResult.Err -> return failPeerOrUsage(result.error)
            is TlsResult.Ok -> result.value
        }
        if (messages.size > 1) {
            return TlsResult.Err(TlsError.Peer.UnexpectedExtraHandshakeData("ClientHello"))
        }
        val message = messages.singleOrNull() ?: return TlsResult.Ok(Transition(s))
        if (s.handshakeDecoder.bufferedByteCount != 0) {
            return TlsResult.Err(TlsError.Peer.UnexpectedExtraHandshakeData("ClientHello"))
        }
        if (message.type != TLS_HANDSHAKE_CLIENT_HELLO_CONTENT_TYPE) {
            return TlsResult.Err(
                TlsError.Peer.UnexpectedHandshakeType(
                    expected = TLS_HANDSHAKE_CLIENT_HELLO_CONTENT_TYPE,
                    actual = message.type,
                ),
            )
        }
        if (message.encodedBytes.size > TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH) {
            return TlsResult.Err(
                TlsError.Peer.ClientHelloTooLarge(
                    size = message.encodedBytes.size,
                    limit = TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH,
                ),
            )
        }

        return when (val parsed = parseClientHello(message.encodedBytes, r.encodedRecord)) {
            is TlsResult.Err -> TlsResult.Err(parsed.error)
            is TlsResult.Ok -> TlsResult.Ok(
                Transition(
                    TlsState.AwaitServerFlight(parsed.value),
                    listOf(ClientTlsEvent.ClientHello(parsed.value)),
                ),
            )
        }
    }

    private fun onAwaitClientFinished(s: TlsState.AwaitClientFinished, r: TlsRecordMessage): TlsResult<Transition> {
        if (r.contentType != TLS_APPLICATION_DATA_CONTENT_TYPE) {
            return TlsResult.Err(
                TlsError.Peer.UnexpectedContentType(
                    expected = TLS_APPLICATION_DATA_CONTENT_TYPE,
                    actual = r.contentType,
                    phase = "EXPECT_CLIENT_FINISHED",
                ),
            )
        }
        val plaintext = when (val result = guard { recordLayer.decode(r) }) {
            is TlsResult.Err -> return failPeerOrUsage(result.error)
            is TlsResult.Ok -> result.value
        }
        val messages = when (val result = guard { s.handshakeDecoder.feed(plaintext.payload) }) {
            is TlsResult.Err -> return failPeerOrUsage(result.error)
            is TlsResult.Ok -> result.value
        }
        if (messages.size > 1) {
            return TlsResult.Err(TlsError.Peer.UnexpectedExtraHandshakeData("ClientFinished"))
        }
        val message = messages.singleOrNull() ?: return TlsResult.Ok(Transition(s))
        if (s.handshakeDecoder.bufferedByteCount != 0) {
            return TlsResult.Err(TlsError.Peer.UnexpectedExtraHandshakeData("ClientFinished"))
        }
        if (message.type != TLS_HANDSHAKE_FINISH_CONTENT_TYPE) {
            return TlsResult.Err(
                TlsError.Peer.UnexpectedHandshakeType(
                    expected = TLS_HANDSHAKE_FINISH_CONTENT_TYPE,
                    actual = message.type,
                ),
            )
        }
        val verified = KeySchedule.verifyClientFinished(message.encodedBytes, s.handshakeSecrets, s.transcriptHash)
        if (!verified) {
            return TlsResult.Err(TlsError.Peer.ClientFinishedVerificationFailed)
        }

        recordLayer.installApplicationKeys(s.applicationSecrets)
        return TlsResult.Ok(Transition(TlsState.Established, listOf(ClientTlsEvent.ClientFinished)))
    }

    private fun onEstablished(r: TlsRecordMessage): TlsResult<Transition> {
        if (r.contentType != TLS_APPLICATION_DATA_CONTENT_TYPE) {
            return TlsResult.Err(
                TlsError.Peer.UnexpectedContentType(
                    expected = TLS_APPLICATION_DATA_CONTENT_TYPE,
                    actual = r.contentType,
                    phase = "APPLICATION_DATA",
                ),
            )
        }

        val plaintext = when (val result = guard { recordLayer.decode(r) }) {
            is TlsResult.Err -> return failPeerOrUsage(result.error)
            is TlsResult.Ok -> result.value
        }
        return TlsResult.Ok(Transition(TlsState.Established, listOf(ClientTlsEvent.ClientApplicationData(plaintext.payload))))
    }

    private fun parseClientHello(
        encoded: ByteArray,
        rawRecordBytes: ByteArray = encoded,
    ): TlsResult<ClientHelloWrapper> {
        if (encoded.size < TLS_HANDSHAKE_HEADER_LENGTH + 35) {
            return TlsResult.Err(TlsError.Peer.MalformedClientHello("ClientHello is truncated"))
        }
        val bodyOffset = TLS_HANDSHAKE_HEADER_LENGTH
        val sessionIdLengthOffset = TLS_HANDSHAKE_HEADER_LENGTH + 2 + 32
        val sessionIdLength = encoded[sessionIdLengthOffset].toInt() and 0xFF
        val sessionIdOffset = sessionIdLengthOffset + 1
        if (sessionIdOffset + sessionIdLength > encoded.size) {
            return TlsResult.Err(TlsError.Peer.MalformedClientHello("ClientHello session ID is truncated"))
        }
        return when (val result = guard {
            val parsed = ClientHello.parse(
                ByteArrayInputStream(encoded, bodyOffset, encoded.size - bodyOffset),
                null,
            )
            if (sessionIdLength != parsed.sessionID.size) {
                error("ClientHello session ID length mismatch")
            }
            ClientHelloWrapper(parsed, encoded, sessionIdOffset, rawRecordBytes)
        }) {
            is TlsResult.Err -> TlsResult.Err(result.error)
            is TlsResult.Ok -> TlsResult.Ok(result.value)
        }
    }

    private fun failPeer(error: TlsError): TlsResult<Nothing> {
        val peer = error as? TlsError.Peer ?: TlsError.Peer.ProcessingFailure(IllegalStateException(error.description))
        state = TlsState.Failed(peer)
        pendingRecords.clear()
        recordLayer.reset()
        plaintextHandshakeDecoder.reset()
        encryptedHandshakeDecoder.reset()
        return TlsResult.Err(peer)
    }

    private fun failPeerOrUsage(error: TlsError): TlsResult<Nothing> {
        val peer = error as? TlsError.Peer
        if (peer != null) return failPeer(peer)
        TlsResult.Err(error)
        return TlsResult.Err(error)
    }

    private inline fun <T> guard(block: () -> T): TlsResult<T> = try {
        TlsResult.Ok(block())
    } catch (e: IllegalArgumentException) {
        TlsResult.Err(TlsError.Peer.ProcessingFailure(e))
    } catch (e: IllegalStateException) {
        TlsResult.Err(TlsError.Peer.ProcessingFailure(e))
    } catch (e: GeneralSecurityException) {
        TlsResult.Err(TlsError.Peer.ProcessingFailure(e))
    } catch (e: IOException) {
        TlsResult.Err(TlsError.Peer.ProcessingFailure(e))
    }
}

