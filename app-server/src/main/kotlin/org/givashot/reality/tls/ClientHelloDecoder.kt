package org.givashot.reality.tls

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.util.ReferenceCountUtil
import org.bouncycastle.tls.ClientHello
import org.givashot.tls.entity.ClientHelloWrapper
import java.io.ByteArrayInputStream
import java.util.logging.Level
import java.util.logging.Logger

private const val TLS_RECORD_HEADER_LENGTH = 5
private const val TLS_HANDSHAKE_CONTENT_TYPE = 0x16
private const val TLS_HANDSHAKE_HEADER_LENGTH = 4
private const val TLS_HANDSHAKE_CLIENT_HELLO_CONTENT_TYPE = 1
private const val MAX_CLIENT_HELLO_LENGTH = 64 * 1024
private const val BODY_OFFSET_BASE_HANDSHAKE = 4


/** Accumulates TLS records until a complete ClientHello can be parsed. */
class ClientHelloDecoder() {
    private val helloRecords = ArrayList<ByteBuf>()
    private var handshakeBuffer: ByteBuf? = null
    private var expectedHandshakeLength: Int? = null
    private var capturedWireBytes = 0L
    private val maxClientHelloWireBytes = MAX_CLIENT_HELLO_LENGTH.toLong() * 6 + TLS_RECORD_HEADER_LENGTH

    fun decode(ctx: ChannelHandlerContext, input: ByteBuf): Result {
        if (input.readableBytes() < TLS_RECORD_HEADER_LENGTH) return Result.NeedMore
        val index = input.readerIndex()
        val contentType = input.getUnsignedByte(index).toInt()
        val majorVersion = input.getUnsignedByte(index + 1).toInt()
        val payloadLength = input.getUnsignedShort(index + 3)
        if (contentType != TLS_HANDSHAKE_CONTENT_TYPE || majorVersion != 3) {
            return Result.Fallback("input is not a TLS handshake record")
        }
        val tlsRecordLength = TLS_RECORD_HEADER_LENGTH + payloadLength
        if (input.readableBytes() < tlsRecordLength) {
            // wait the full tls record data
            return Result.NeedMore
        }
        if (capturedWireBytes + tlsRecordLength > maxClientHelloWireBytes) {
            return Result.Fallback("ClientHello wire size exceeds configured limit")
        }

        val record = input.readRetainedSlice(tlsRecordLength)
        helloRecords += record
        capturedWireBytes += tlsRecordLength
        val handshake = handshakeBuffer ?: ctx.alloc().buffer().also { handshakeBuffer = it }
        handshake.writeBytes(record, TLS_RECORD_HEADER_LENGTH, payloadLength)

        if (handshake.readableBytes() >= TLS_HANDSHAKE_HEADER_LENGTH
            && expectedHandshakeLength == null
        ) {
            val start = handshake.readerIndex()
            if (handshake.getUnsignedByte(start).toInt() != TLS_HANDSHAKE_CLIENT_HELLO_CONTENT_TYPE) {
                return Result.Fallback("first handshake message is not ClientHello")
            }
            val bodyLength = handshake.getUnsignedMedium(start + 1)
            if (bodyLength > MAX_CLIENT_HELLO_LENGTH) {
                return Result.Fallback("ClientHello exceeds configured limit")
            }
            expectedHandshakeLength = TLS_HANDSHAKE_HEADER_LENGTH + bodyLength
        }

        val expected = expectedHandshakeLength
        if (expected != null && handshake.readableBytes() >= expected) {
            if (handshake.readableBytes() != expected) {
                return Result.Fallback("ClientHello shares a record with additional handshake data")
            }
            val handshakeAndBody = ByteArray(expected).also { handshake.getBytes(handshake.readerIndex(), it) }
            val hello = runCatching { parseClientHello(handshakeAndBody) }
                .onFailure { logger.log(Level.FINE, "Could not parse ClientHello", it) }
                .getOrNull()
                ?: return Result.Fallback("malformed ClientHello")
            return Result.Complete(hello)
        }
        return Result.NeedMore
    }

    fun takeHelloRecords(ctx: ChannelHandlerContext): ByteBuf? {
        if (helloRecords.isEmpty()) return null
        val composite = ctx.alloc().compositeBuffer(helloRecords.size)
        helloRecords.forEach { composite.addComponent(true, it) }
        helloRecords.clear()
        return composite
    }

    fun release() {
        helloRecords.forEach(ReferenceCountUtil::release)
        helloRecords.clear()
        handshakeBuffer?.release()
        handshakeBuffer = null
    }

    private fun parseClientHello(handshakeAndBody: ByteArray): ClientHelloWrapper {
        require(handshakeAndBody.size >= BODY_OFFSET_BASE_HANDSHAKE + 35) { "ClientHello is truncated" }
        val bodyOffset = BODY_OFFSET_BASE_HANDSHAKE
        val sessionIdOffset = bodyOffset + 2 + 32 + 1
        val parsed = ClientHello.parse(
            ByteArrayInputStream(handshakeAndBody, bodyOffset, handshakeAndBody.size - bodyOffset),
            null,
        )
        require((handshakeAndBody[sessionIdOffset - 1].toInt() and 0xff) == parsed.sessionID.size) {
            "Session ID length mismatch"
        }
        return ClientHelloWrapper(parsed, handshakeAndBody, sessionIdOffset)
    }

    sealed class Result {
        data object NeedMore : Result()
        data class Complete(val hello: ClientHelloWrapper) : Result()
        data class Fallback(val reason: String) : Result()
    }

    companion object {
        private val logger = Logger.getLogger(ClientHelloDecoder::class.java.name)
    }
}
