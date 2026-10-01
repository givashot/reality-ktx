package org.givashot.reality.manager.connection

import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.ByteToMessageDecoder
import org.givashot.reality.authentication.AuthResult
import org.givashot.reality.tls.RealityTLSHandshakeService
import org.givashot.reality.tls.TlsConnectionState
import org.givashot.reality.tls.TlsHandshakePhase
import org.givashot.tls.constant.TLS_MAX_RECORD_SIZE
import org.givashot.tls.constant.TLS_RECORD_HEADER_LENGTH
import org.givashot.tls.decryptApplicationData
import org.givashot.tls.decryptHandshakeRecord
import org.givashot.tls.deriveApplicationSecrets
import org.givashot.tls.entity.handshake.ClientHelloWrapper
import org.givashot.tls.verifyClientFinishedMessage
import java.util.logging.Level
import java.util.logging.Logger



/** Processes complete TLS records while retaining partial records in Netty's cumulation buffer. */
class ConnectionHandler(
    private val connectionManager: ConnectionManager,
    private val clientHelloWrapper: ClientHelloWrapper,
    private val result: AuthResult.Success,
) : ByteToMessageDecoder() {

    private val clientFinished = ClientFinishedAccumulator()
    private var closing = false

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        connectionManager.onAuthenticated(ctx.channel(), clientHelloWrapper, result)
    }

    override fun decode(ctx: ChannelHandlerContext, input: ByteBuf, out: MutableList<Any>) {
        while (input.readableBytes() >= TLS_RECORD_HEADER_LENGTH) {
            val index = input.readerIndex()
            val recordLength = input.getUnsignedShort(index + 3)
            val tlsRecordLength = TLS_RECORD_HEADER_LENGTH + recordLength
            if (input.readableBytes() < tlsRecordLength) {
                // wait full tls record
                return
            }

            if (tlsRecordLength > TLS_MAX_RECORD_SIZE) {
                close(ctx, "TLS record exceeds maximum size limit")
                return
            }

            val record = ByteArray(tlsRecordLength)
            input.readBytes(record)
            val state = ctx.channel().attr(RealityTLSHandshakeService.TLS_STATE_KEY).get()
            if (state == null) {
                close(ctx, "TLS state missing")
                return
            }

            when (state.phase) {
                TlsHandshakePhase.SERVER_FLIGHT_SENT -> processHandshakeRecord(ctx, record, state)
                TlsHandshakePhase.APPLICATION_DATA -> processApplicationRecord(ctx, record, state)
                else -> {
                    close(ctx, "unexpected TLS record while in ${state.phase}")
                    return
                }
            }
            if (closing || !ctx.channel().isActive) return
        }
    }

    private fun processHandshakeRecord(
        ctx: ChannelHandlerContext,
        record: ByteArray,
        state: TlsConnectionState,
    ) {
        val plaintext = runCatching {
            decryptHandshakeRecord(record, state.handshakeSecrets, state.clientHandshakeSequenceNumber)
        }.getOrElse {
            close(ctx, "could not decrypt client handshake record", it)
            return
        }
        state.clientHandshakeSequenceNumber++
        val message = try {
            clientFinished.append(plaintext, state.handshakeSecrets.cipherSuite.hashLength)
        } catch (cause: IllegalArgumentException) {
            close(ctx, cause.message ?: "malformed Client Finished", cause)
            return
        } ?: return
        val transcriptHash = state.serverFlightTranscriptHash
        if (transcriptHash == null || !verifyClientFinishedMessage(
                message,
                state.handshakeSecrets,
                transcriptHash,
            )
        ) {
            close(ctx, "Client Finished verification failed")
            return
        }
        state.applicationSecrets = deriveApplicationSecrets(state.handshakeSecrets, transcriptHash)
        state.transcript += message
        state.phase = TlsHandshakePhase.APPLICATION_DATA
        state.clientApplicationSequenceNumber = 0
    }

    private fun processApplicationRecord(
        ctx: ChannelHandlerContext,
        record: ByteArray,
        state: TlsConnectionState,
    ) {
        val secrets = state.applicationSecrets
        if (secrets == null) {
            close(ctx, "application secrets missing")
            return
        }
        val plaintext = runCatching {
            decryptApplicationData(record, secrets, state.clientApplicationSequenceNumber)
        }.getOrElse {
            close(ctx, "could not decrypt application record", it)
            return
        }
        state.clientApplicationSequenceNumber++
        ctx.fireChannelRead(Unpooled.wrappedBuffer(plaintext))
    }

    private fun close(ctx: ChannelHandlerContext, reason: String, cause: Throwable? = null) {
        if (closing) return
        closing = true
        val phase = ctx.channel().attr(RealityTLSHandshakeService.TLS_STATE_KEY).get()?.phase ?: "unknown"
        if (cause == null) logger.warning("Closing TLS connection in phase $phase: $reason")
        else logger.log(Level.WARNING, "Closing TLS connection in phase $phase: $reason", cause)
        ctx.close()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        close(ctx, "connection handler exception", cause)
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        ctx.channel().attr(RealityTLSHandshakeService.TLS_STATE_KEY).get()?.phase = TlsHandshakePhase.CLOSED
        super.channelInactive(ctx)
    }

    companion object {
        private val logger = Logger.getLogger(ConnectionHandler::class.java.name)
    }
}

/**
 * Bounded TLS handshake-message reassembly across independently encrypted records. */
internal class ClientFinishedAccumulator {
    private val bytes = java.io.ByteArrayOutputStream()
    private var expectedLength: Int? = null

    /** Returns the complete Finished message, or null while more record plaintext is required. */
    fun append(fragment: ByteArray, hashLength: Int): ByteArray? {
        require(hashLength == 32 || hashLength == 48)
        val currentExpected = expectedLength
        require(currentExpected == null || bytes.size() < currentExpected) { "Finished message is already complete" }
        bytes.write(fragment)
        val message = bytes.toByteArray()
        if (message.size >= 4 && expectedLength == null) {
            require((message[0].toInt() and 0xff) == 20) { "expected Client Finished handshake message" }
            val bodyLength = ((message[1].toInt() and 0xff) shl 16) or
                ((message[2].toInt() and 0xff) shl 8) or
                (message[3].toInt() and 0xff)
            require(bodyLength == hashLength) { "invalid Client Finished length $bodyLength" }
            expectedLength = bodyLength + 4
        }
        val expected = expectedLength ?: return null
        require(message.size <= expected) { "unexpected handshake data after Client Finished" }
        return message.takeIf { it.size == expected }
    }
}
