package org.givashot.reality.tls

import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.ByteToMessageDecoder
import io.netty.handler.timeout.ReadTimeoutException
import io.netty.handler.timeout.ReadTimeoutHandler
import org.givashot.reality.authentication.AuthResult
import org.givashot.reality.authentication.Authenticator
import org.givashot.reality.fallback.FallbackHandlerFactory
import org.givashot.tls.ServerProfile
import org.givashot.tls.handshake.EncryptedExtensionsData
import org.givashot.tls.session.ClientTlsEvent
import org.givashot.tls.session.TlsError
import org.givashot.tls.session.TlsResult
import org.givashot.tls.session.TlsServerStateMachine
import java.util.logging.Level
import java.util.logging.Logger

class RealityTlsConnectionHandler(
    private val authenticator: Authenticator,
    private val handshakeRecordProfile: HandshakeRecordProfile,
    private val fallbackHandlerFactory: FallbackHandlerFactory,
) : ByteToMessageDecoder() {

    private val tlsStateMachine = TlsServerStateMachine(
        ServerProfile(recordLengths = handshakeRecordProfile.recordLengths),
    )
    private var authenticated = false
    private var switchedToFallback = false

    override fun decode(ctx: ChannelHandlerContext, input: ByteBuf, out: MutableList<Any>) {
        if (switchedToFallback || !input.isReadable) return

        val bytes = ByteArray(input.readableBytes())
        input.readBytes(bytes)

        when (val result = tlsStateMachine.processClientData(bytes)) {
            is TlsResult.Ok -> processEvents(ctx, result.value)
            is TlsResult.Err -> {
                val cause = RuntimeException(result.error.description)
                when (val error = result.error) {
                    is TlsError.Peer -> {
                        logger.log(Level.FINE, "TLS peer error: ${error.description}")
                        if (authenticated) close(ctx, "TLS peer error", cause)
                        else switchToFallback(ctx, "malformed or unsupported TLS ClientHello", cause)
                    }
                    is TlsError.Usage -> {
                        logger.log(Level.WARNING, "TLS usage error: ${error.description}")
                        close(ctx, "TLS misuse", cause)
                    }
                }
            }
        }
    }

    private fun processEvents(ctx: ChannelHandlerContext, events: List<ClientTlsEvent>) {
        for (event in events) {
            when (event) {
                is ClientTlsEvent.ClientHello -> {
                    check(!authenticated) { "Received a second ClientHello" }
                    when (val result = authenticator.doAuth(event.hello)) {
                        is AuthResult.Failure -> switchToFallback(ctx, result.reason.toString())
                        is AuthResult.Success -> sendServerFlight(ctx, result.authKey)
                    }
                }

                is ClientTlsEvent.ClientFinished -> Unit
                is ClientTlsEvent.ClientApplicationData ->
                    ctx.fireChannelRead(Unpooled.wrappedBuffer(event.data))
            }
        }
    }

    private fun sendServerFlight(ctx: ChannelHandlerContext, authKey: ByteArray) {
        authenticated = true
        try {
            val certificate = applyAuthKeySignature(authKey)
            val records = when (val result = tlsStateMachine.buildServerFlight(
                encryptedExtensions = EncryptedExtensionsData(),
                certificate = certificate,
            )) {
                is TlsResult.Ok -> result.value
                is TlsResult.Err -> {
                    val cause = RuntimeException(result.error.description)
                    when (result.error) {
                        is TlsError.Peer -> close(ctx, "TLS peer error while building server flight", cause)
                        is TlsError.Usage -> close(ctx, "TLS usage error while building server flight", cause)
                    }
                    return
                }
            }
            ctx.writeAndFlush(Unpooled.wrappedBuffer(*records.toTypedArray()))
            when (val result = tlsStateMachine.processClientData(ByteArray(0))) {
                is TlsResult.Ok -> processEvents(ctx, result.value)
                is TlsResult.Err -> {
                    val error = result.error
                    close(ctx, "Could not advance TLS state after server flight", RuntimeException(error.description))
                }
            }
        } catch (cause: Exception) {
            close(ctx, "Could not build or send TLS server flight", cause)
        }
    }

    private fun switchToFallback(ctx: ChannelHandlerContext, reason: String, cause: Throwable? = null) {
        if (switchedToFallback || authenticated) return
        switchedToFallback = true
        tlsStateMachine.close()
        if (cause == null) logger.fine("Switching unauthenticated connection to fallback: $reason")
        else logger.log(Level.FINE, "Switching unauthenticated connection to fallback: $reason", cause)

        try {
            val replay = tlsStateMachine.rawClientHelloBytes()?.takeIf { it.isNotEmpty() }?.let { Unpooled.wrappedBuffer(it) }
            switchHandler(ctx, fallbackHandlerFactory.newForwardHandler(replay))
        } catch (failure: Exception) {
            logger.log(Level.WARNING, "Could not switch connection to fallback", failure)
            ctx.close()
        }
    }

    private fun switchHandler(ctx: ChannelHandlerContext, handler: ChannelHandler) {
        ctx.pipeline().get(ReadTimeoutHandler::class.java)?.let { ctx.pipeline().remove(it) }
        ctx.pipeline().addAfter(ctx.name(), null, handler)
        ctx.pipeline().remove(this)
    }

    private fun close(ctx: ChannelHandlerContext, reason: String, cause: Throwable) {
        if (!ctx.channel().isActive) return
        logger.log(Level.WARNING, "$reason in TLS phase ${tlsStateMachine.phase}", cause)
        tlsStateMachine.close()
        ctx.close()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        if (cause is ReadTimeoutException) {
            switchToFallback(ctx, "authentication read timed out")
        } else if (authenticated) {
            close(ctx, "TLS connection handler failed", cause)
        } else {
            switchToFallback(ctx, "TLS connection handler failed", cause)
        }
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        tlsStateMachine.close()
        super.channelInactive(ctx)
    }

    override fun handlerRemoved0(ctx: ChannelHandlerContext) {
        super.handlerRemoved0(ctx)
    }

    companion object {
        private val logger = Logger.getLogger(RealityTlsConnectionHandler::class.java.name)
    }
}
