package org.givashot.reality.authentication

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.ssl.SslClientHelloHandler
import io.netty.handler.timeout.ReadTimeoutHandler
import io.netty.util.concurrent.Future
import org.bouncycastle.tls.ClientHello
import org.givashot.reality.fallback.FallbackService
import org.givashot.reality.manager.connection.ConnectionHandler
import org.givashot.reality.manager.connection.ConnectionManager
import org.givashot.tls.BODY_OFFSET_BASE_HANDSHAKE
import org.givashot.tls.BODY_OFFSET_BASE_TLS_RECORD
import org.givashot.tls.ClientHelloWrapper
import java.io.ByteArrayInputStream

private const val DEFAULT_MAX_CLIENT_HELLO_LENGTH = 64 * 1024

class AuthenticationHandler(
    private val authenticator: Authenticator,
    private val connectionManager: ConnectionManager,
    private val fallbackService: FallbackService,
    maxClientHelloLength: Int = DEFAULT_MAX_CLIENT_HELLO_LENGTH,
) : SslClientHelloHandler<ClientHelloWrapper?>(maxClientHelloLength) {

    override fun lookup(
        ctx: ChannelHandlerContext,
        clientHello: ByteBuf?,
    ): Future<ClientHelloWrapper?> {
        val parsed = clientHello?.let { buf ->
            runCatching {
                val raw = ByteArray(buf.readableBytes()).also { buf.readBytes(it) }
                val bodyOffset = raw.determineClientHelloBodyOffset()
                // 统一得到「Handshake 头 + Body」
                val handshakeAndBody: ByteArray = when (bodyOffset) {
                    0 -> {
                        // Netty 只给了 Body，需要补 4 字节 Handshake 头
                        // type = 0x01 (ClientHello), length = body 长度（3 字节大端）
                        val bodyLen = raw.size
                        ByteArray(4 + bodyLen).also { out ->
                            out[0] = 0x01
                            out[1] = ((bodyLen ushr 16) and 0xFF).toByte()
                            out[2] = ((bodyLen ushr 8) and 0xFF).toByte()
                            out[3] = (bodyLen and 0xFF).toByte()
                            System.arraycopy(raw, 0, out, 4, bodyLen)
                        }
                    }
                    BODY_OFFSET_BASE_HANDSHAKE -> raw
                    BODY_OFFSET_BASE_TLS_RECORD -> raw.copyOfRange(5, raw.size)
                    else -> throw RuntimeException("never happen")
                }
                parseClientHello(handshakeAndBody)
            }.getOrNull()
        }
        return ctx.executor().newSucceededFuture(parsed)
    }

    override fun onLookupComplete(
        ctx: ChannelHandlerContext,
        future: Future<ClientHelloWrapper?>,
    ) {
        val clientHello = future.getNow()
        if (clientHello == null) {
            switchToFallback(ctx)
            return
        }

        when (val result = authenticator.doAuth(clientHello)) {
            is AuthResult.Success -> switchTo(
                ctx,
                ConnectionHandler(connectionManager, clientHello, result),
            )

            is AuthResult.Failure -> switchToFallback(ctx)
        }
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        switchToFallback(ctx)
    }

    private fun switchToFallback(ctx: ChannelHandlerContext) {
        switchTo(ctx, fallbackService.newForwardHandler())
    }

    private fun switchTo(ctx: ChannelHandlerContext, handler: ChannelHandler) {
        ctx.pipeline().get(ReadTimeoutHandler::class.java)?.let { ctx.pipeline().remove(it) }
        ctx.pipeline().addAfter(ctx.name(), null, handler)
        ctx.pipeline().remove(this)
    }

    /**
     * 智能判断并剥离 TLS Record Header (5 Bytes) 与 Handshake Header (4 Bytes)
     */
    private fun ByteArray.determineClientHelloBodyOffset(): Int {
        val input = this
        val size = input.size

        // 情况 1: 完整的 TLS Record 报文 (Record Header 5 Bytes + Handshake Header 4 Bytes)
        // 0x16 = Handshake; Byte 3~4 = Record Length; Byte 5 = 0x01 (Client Hello)
        if (size >= 9 && input[0] == 0x16.toByte()) {
            val recordLength = ((input[3].toInt() and 0xFF) shl 8) or (input[4].toInt() and 0xFF)
            val handshakeType = input[5]

            // 校验 Record Length 是否合理，且 Handshake Type 为 ClientHello (1)
            if (handshakeType == 1.toByte() && size >= 5 + recordLength) {
                val handshakeLength = ((input[6].toInt() and 0xFF) shl 16) or
                        ((input[7].toInt() and 0xFF) shl 8) or
                        (input[8].toInt() and 0xFF)

                // 确保数据包长度足够容纳完整 Handshake Body
                if (size >= 9 + handshakeLength) {
                    return BODY_OFFSET_BASE_TLS_RECORD
                }
            }
        }

        // 情况 2: 纯 Handshake 报文 (Handshake Header 4 Bytes + Handshake Body)
        // Byte 0 = 0x01 (Client Hello); Byte 1~3 = Handshake Length (Uint24)
        if (size >= 4 && input[0] == 1.toByte()) {
            val handshakeLength = ((input[1].toInt() and 0xFF) shl 16) or
                    ((input[2].toInt() and 0xFF) shl 8) or
                    (input[3].toInt() and 0xFF)

            // 防误判关键：计算出来的 handshakeLength 必须刚好等于剩余字节数 (size - 4)
            if (size == 4 + handshakeLength) {
                return BODY_OFFSET_BASE_HANDSHAKE
            }
        }

        // 情况 3: 已经由 Netty 剥离好的纯 ClientHello Body (无 Record & Handshake Header)
        return 0
    }

    private fun parseClientHello(handshakeAndBody: ByteArray): ClientHelloWrapper {
        require(handshakeAndBody.isNotEmpty()) { "ClientHello must not be empty" }
        return try {
            // Netty's SslClientHelloHandler supplies the ClientHello body. Tests and
            // callers may instead pass a complete TLS record or handshake message.
            val bodyOffset = BODY_OFFSET_BASE_HANDSHAKE
            require(handshakeAndBody.size >= bodyOffset + 35) { "ClientHello is truncated" }

            // legacy_version (2) + random (32) + session_id_length (1)
            val sessionIdOffset = bodyOffset + 2 + 32 + 1
            val stream = ByteArrayInputStream(handshakeAndBody, bodyOffset, handshakeAndBody.size - bodyOffset)

            val parsed = ClientHello.parse(stream, null)

            val actualSessionIdLength = parsed.sessionID.size
            require(handshakeAndBody[sessionIdOffset - 1].toInt() and 0xFF == actualSessionIdLength) {
                "Session ID length mismatch during offset calculation"
            }
            ClientHelloWrapper(
                base = parsed,
                handshakeAndBody = handshakeAndBody.copyOf(),
                sessionIdOffset = sessionIdOffset,
            )
        } catch (cause: Exception) {
            throw Exception("Malformed ClientHello: ${cause.message}")
        }
    }

}
