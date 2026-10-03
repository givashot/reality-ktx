package org.givashot.reality.tls

import io.netty.buffer.Unpooled
import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.ByteToMessageDecoder
import io.netty.handler.timeout.ReadTimeoutException
import io.netty.handler.timeout.ReadTimeoutHandler
import org.givashot.reality.authentication.AuthResult
import org.givashot.reality.authentication.Authenticator
import org.givashot.reality.fallback.FallbackHandlerFactory
import org.givashot.tls.ServerProfile
import org.givashot.tls.connection.TlsCommand
import org.givashot.tls.connection.TlsConnection
import org.givashot.tls.connection.TlsConnectionResult
import org.givashot.tls.connection.TlsError
import org.givashot.tls.connection.TlsEvent
import org.givashot.tls.handshake.EncryptedExtensionsData
import java.util.logging.Level
import java.util.logging.Logger

class RealityTlsConnectionHandler(
    private val authenticator: Authenticator,
    private val handshakeRecordProfile: HandshakeRecordProfile,
    private val fallbackHandlerFactory: FallbackHandlerFactory,
) : ByteToMessageDecoder() {

    private val connection = TlsConnection.create(
        ServerProfile(recordLengths = handshakeRecordProfile.recordLengths),
    )
    private var authenticated = false
    private var switchedToFallback = false

    override fun decode(ctx: ChannelHandlerContext, input: ByteBuf, out: MutableList<Any>) {
        if (switchedToFallback || !input.isReadable) return

        val bytes = ByteArray(input.readableBytes())
        input.readBytes(bytes)

        when (val result = connection.receive(bytes)) {
            is TlsConnectionResult.Ok -> processResult(ctx, result)
            is TlsConnectionResult.Err -> handleError(ctx, result.error, "receiving client data")
        }
    }

    private fun handleError(ctx: ChannelHandlerContext, error: TlsError, action: String) {
        val cause = RuntimeException(error.description)
        when (error) {
            is TlsError.Peer -> {
                logger.log(Level.FINE, "TLS peer error: ${error.description}")
                if (authenticated) close(ctx, "TLS peer error while $action", cause)
                else switchToFallback(ctx, "malformed or unsupported TLS ClientHello", cause)
            }
            is TlsError.Usage -> {
                logger.log(Level.WARNING, "TLS usage error: ${error.description}")
                close(ctx, "TLS misuse while $action", cause)
            }
        }
    }

    private fun processResult(ctx: ChannelHandlerContext, result: TlsConnectionResult.Ok) {
        if (result.outbound.isNotEmpty()) {
            ctx.writeAndFlush(Unpooled.wrappedBuffer(*result.outbound.toTypedArray()))
        }
        for (event in result.events) {
            if (switchedToFallback) return
            when (event) {
                is TlsEvent.ClientHello -> {
                    check(!authenticated) { "Received a second ClientHello" }
                    when (val auth = authenticator.doAuth(event.hello)) {
                        is AuthResult.Failure -> switchToFallback(ctx, auth.reason.toString())
                        is AuthResult.Success -> sendServerFlight(ctx, auth.authKey)
                    }
                }

                is TlsEvent.ClientFinished -> Unit
                is TlsEvent.ClientApplicationData -> ctx.fireChannelRead(Unpooled.wrappedBuffer(event.data))
            }
        }
    }

    private fun sendServerFlight(ctx: ChannelHandlerContext, authKey: ByteArray) {
        authenticated = true
        try {
            val certificate = applyAuthKeySignature(authKey)
            when (val result = connection.execute(
                TlsCommand.SendServerFlight(EncryptedExtensionsData(), certificate),
            )) {
                is TlsConnectionResult.Ok -> processResult(ctx, result)
                is TlsConnectionResult.Err -> handleError(ctx, result.error, "building server flight")
            }
        } catch (cause: Exception) {
            close(ctx, "Could not build or send TLS server flight", cause)
        }
    }

    private fun switchToFallback(ctx: ChannelHandlerContext, reason: String, cause: Throwable? = null) {
        if (switchedToFallback || authenticated) return
        switchedToFallback = true
        val replayBytes = connection.unauthenticatedInboundBytes()
        connection.close()
        if (cause == null) logger.fine("Switching unauthenticated connection to fallback: $reason")
        else logger.log(Level.FINE, "Switching unauthenticated connection to fallback: $reason", cause)

        try {
            val replay = replayBytes.takeIf { it.isNotEmpty() }?.let { Unpooled.wrappedBuffer(it) }
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
        logger.log(Level.WARNING, "$reason in TLS state ${connection.state}", cause)
        connection.close()
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
        connection.close()
        super.channelInactive(ctx)
    }

    override fun handlerRemoved0(ctx: ChannelHandlerContext) {
        super.handlerRemoved0(ctx)
    }

    companion object {
        private val logger = Logger.getLogger(RealityTlsConnectionHandler::class.java.name)
    }
}
