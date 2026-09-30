package org.givashot.reality.authentication

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.ByteToMessageDecoder
import io.netty.handler.timeout.ReadTimeoutException
import io.netty.handler.timeout.ReadTimeoutHandler
import org.givashot.reality.fallback.FallbackService
import org.givashot.reality.manager.connection.ConnectionHandler
import org.givashot.reality.manager.connection.ConnectionManager
import org.givashot.reality.tls.ClientHelloDecoder
import java.util.logging.Level
import java.util.logging.Logger


/** Reads complete TLS records so an unauthenticated ClientHello can be replayed byte-for-byte. */
class AuthenticationHandler(
    private val authenticator: Authenticator,
    private val connectionManager: ConnectionManager,
    private val fallbackService: FallbackService,
) : ByteToMessageDecoder() {

    private val clientHelloDecoder = ClientHelloDecoder()
    private var switched = false

    override fun decode(ctx: ChannelHandlerContext, input: ByteBuf, out: MutableList<Any>) {
        if (switched) return
        when (val result = clientHelloDecoder.decode(ctx, input)) {
            ClientHelloDecoder.Result.NeedMore -> return
            is ClientHelloDecoder.Result.Fallback -> switchToFallback(ctx, result.reason)
            is ClientHelloDecoder.Result.Complete ->{
                when (val auth = authenticator.doAuth(result.hello)) {
                    is AuthResult.Success -> switchTo(
                        ctx,
                        ConnectionHandler(connectionManager, result.hello, auth),
                        replayHello = false,
                    )

                    is AuthResult.Failure -> switchToFallback(ctx, "ClientHello authentication failed")
                }
            }
        }
    }

    private fun switchToFallback(ctx: ChannelHandlerContext, reason: String) {
        logger.fine("Switching connection to fallback: $reason")
        val initialBytes = clientHelloDecoder.takeHelloRecords(ctx)
        switchTo(ctx, fallbackService.newForwardHandler(initialBytes), replayHello = true)
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        if (cause is ReadTimeoutException) logger.fine("Authentication read timed out; forwarding to fallback")
        else logger.log(Level.WARNING, "Authentication pipeline failed; forwarding to fallback", cause)
        switchToFallback(ctx, "authentication pipeline exception")
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        clientHelloDecoder.release()
        super.channelInactive(ctx)
    }

    private fun switchTo(ctx: ChannelHandlerContext, handler: io.netty.channel.ChannelHandler, replayHello: Boolean) {
        if (switched) return
        switched = true
        if (!replayHello) clientHelloDecoder.release()
        ctx.pipeline().get(ReadTimeoutHandler::class.java)?.let { ctx.pipeline().remove(it) }
        ctx.pipeline().addAfter(ctx.name(), null, handler)
        ctx.pipeline().remove(this)
    }

    override fun handlerRemoved0(ctx: ChannelHandlerContext) {
        clientHelloDecoder.release()
        super.handlerRemoved0(ctx)
    }

    companion object {
        private val logger = Logger.getLogger(AuthenticationHandler::class.java.name)
    }
}
