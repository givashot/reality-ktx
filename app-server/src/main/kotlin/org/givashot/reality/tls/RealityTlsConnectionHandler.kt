package org.givashot.reality.tls

import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.ByteToMessageDecoder
import io.netty.handler.timeout.IdleStateHandler
import io.netty.handler.timeout.ReadTimeoutHandler
import io.netty.util.AttributeKey
import org.givashot.reality.authentication.AuthResult
import org.givashot.reality.authentication.Authenticator
import org.givashot.reality.fallback.FallbackHandlerFactory
import org.givashot.tls.ServerProfile
import org.givashot.tls.connection.TlsClientEvent
import org.givashot.tls.connection.TlsCommand
import org.givashot.tls.connection.TlsConnection
import org.givashot.tls.connection.TlsUsageException
import org.givashot.tls.handshake.EncryptedExtensionsData
import java.util.logging.Level
import java.util.logging.Logger

class RealityTlsConnectionHandler(
    private val authenticator: Authenticator,
    private val handshakeRecordProfile: HandshakeRecordProfile,
    private val fallbackHandlerFactory: FallbackHandlerFactory,
) : ByteToMessageDecoder() {

    private val connection = TlsConnection.create(
        ServerProfile(),
    )

    private var initByteBuf: ByteBuf? = null
    private var authenticated = false
    private var switchedToFallback = false
    private var handlerContext: ChannelHandlerContext? = null

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        handlerContext = ctx
        super.handlerAdded(ctx)
    }

    /**
     * Encrypts [data] into application data records and writes them. Takes ownership of [data].
     */
    fun writeApplicationData(data: ByteBuf): ChannelFuture {
        val ctx = handlerContext ?: run {
            data.release()
            throw IllegalStateException("TLS handler is not attached to a pipeline")
        }
        return try {
            val bytes = ByteArray(data.readableBytes())
            data.getBytes(data.readerIndex(), bytes)
            val records = connection.execute(TlsCommand.SendApplicationData(bytes))
            ctx.writeAndFlush(Unpooled.wrappedBuffer(*records.toTypedArray()))
        } catch (failure: Exception) {
            ctx.newFailedFuture(failure)
        } finally {
            data.release()
        }
    }

    /**
     * Sends a TLS close_notify alert and then closes the channel. Falls back to a plain close if the alert
     * cannot be produced.
     */
    fun closeWithCloseNotify() {
        val ctx = handlerContext ?: return
        if (!ctx.channel().isActive) return
        try {
            val records = connection.execute(TlsCommand.Close)
            ctx.writeAndFlush(Unpooled.wrappedBuffer(*records.toTypedArray()))
                .addListener(ChannelFutureListener.CLOSE)
        } catch (failure: Exception) {
            ctx.close()
        }
    }

    override fun decode(ctx: ChannelHandlerContext, input: ByteBuf, out: MutableList<Any>) {
        if (switchedToFallback || !input.isReadable || input.readableBytes() <= 0) return

        if (!authenticated) {
            if (initByteBuf == null) {
                initByteBuf = ctx.alloc().buffer()
            }
            initByteBuf!!.writeBytes(input, input.readerIndex(), input.readableBytes())
        } else {
            initByteBuf?.release()
            initByteBuf = null
        }

        val bytes = ByteArray(input.readableBytes())
        input.readBytes(bytes)

        val tlsClientEvents = connection.receive(bytes)
        tlsClientEvents.forEach { event ->
            if (switchedToFallback) return@forEach
            when (event) {
                is TlsClientEvent.ClientAlert -> {
                    if (event.reply != null) {
                        closeAfterWrite(
                            ctx,
                            writeOutbound(ctx, event.reply!!),
                            "received a close notify"
                        )
                    } else {
                        close(ctx, "received a fatal alert or user cancelled")
                    }
                }

                is TlsClientEvent.ClientHello -> {
                    check(!authenticated) { "Received a second ClientHello" }
                    when (val auth = authenticator.doAuth(event.hello)) {
                        is AuthResult.Failure -> switchToFallback(ctx, auth.reason.toString())
                        is AuthResult.Success -> {
                            authenticated = true
                            sendServerFlight(ctx, auth.authKey)
                        }
                    }
                }

                TlsClientEvent.ClientFinished -> {
                    // handshake done, switch to long-live connection
                    ctx.pipeline().get(ReadTimeoutHandler::class.java)?.let { ctx.pipeline().remove(it) }
                    ctx.pipeline().addBefore(
                        ctx.name(), null,
                        IdleStateHandler(0, 0, IDLE_TIMEOUT_SECONDS)
                    )
                }

                is TlsClientEvent.ClientApplicationData -> {
                    ctx.fireChannelRead(Unpooled.wrappedBuffer(event.data))
                }

                is TlsClientEvent.ClientKeyUpdate -> {
                    event.reply?.let {
                        writeOutbound(ctx, it)
                    }
                }

                is TlsClientEvent.ClientError -> {
                    if (!authenticated) {
                        switchToFallback(
                            ctx,
                            event.peerProtocolException.message.toString(),
                            event.peerProtocolException
                        )
                    } else {
                        closeAfterWrite(
                            ctx,
                            writeOutbound(ctx, event.reply),
                            event.peerProtocolException.message,
                            event.peerProtocolException
                        )
                    }
                }
            }
        }
    }

    private fun writeOutbound(ctx: ChannelHandlerContext, vararg records: ByteArray): ChannelFuture? =
        if (records.isEmpty()) null
        else ctx.writeAndFlush(Unpooled.wrappedBuffer(*records))

    private fun closeAfterWrite(
        ctx: ChannelHandlerContext,
        writeFuture: ChannelFuture?,
        reason: String? = null,
        cause: Throwable? = null
    ) {
        if (writeFuture == null) close(ctx, reason, cause)
        else writeFuture.addListener(ChannelFutureListener { close(ctx, reason, cause) })
    }

    private fun sendServerFlight(ctx: ChannelHandlerContext, authKey: ByteArray) {
        val certificate = applyAuthKeySignature(authKey)
        val reply = connection.execute(
            TlsCommand.SendServerFlight(
                EncryptedExtensionsData(),
                certificate,
                handshakeRecordProfile.recordLengths
            )
        )
        writeOutbound(ctx, *reply.toTypedArray())
    }

    private fun switchToFallback(ctx: ChannelHandlerContext, reason: String, cause: Throwable? = null) {
        if (switchedToFallback || authenticated) return
        switchedToFallback = true
        connection.close(cause)
        if (cause == null) logger.fine("Switching unauthenticated connection to fallback: $reason")
        else logger.log(Level.FINE, "Switching unauthenticated connection to fallback: $reason", cause)

        try {
            switchHandler(ctx, fallbackHandlerFactory.newForwardHandler(initByteBuf))
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

    private fun close(ctx: ChannelHandlerContext, reason: String? = null, cause: Throwable? = null) {
        if (!ctx.channel().isActive) return
        ctx.channel().attr(CLOSE_CAUSE_KEY).set(cause)
        logger.log(Level.WARNING, "${reason.toString()} in TLS state ${connection.state}", cause)
        ctx.close()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        if (authenticated) {
            if (cause is TlsUsageException) {
                closeAfterWrite(
                    ctx,
                    writeOutbound(ctx, cause.replyAlertRecord),
                    cause.message,
                    cause
                )
            }
            close(ctx, "TLS connection handler failed", cause)
        } else {
            switchToFallback(ctx, "TLS connection handler failed", cause)
        }
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        connection.close(ctx.channel().attr(CLOSE_CAUSE_KEY).get())
        initByteBuf?.release()
        super.channelInactive(ctx)
    }

    override fun handlerRemoved0(ctx: ChannelHandlerContext) {
        handlerContext = null
        super.handlerRemoved0(ctx)
    }

    companion object {
        private val logger = Logger.getLogger(RealityTlsConnectionHandler::class.java.name)

        private const val IDLE_TIMEOUT_SECONDS = 300

        private val CLOSE_CAUSE_KEY = AttributeKey.valueOf<Throwable>("CLOSE_CAUSE_KEY")
    }
}
