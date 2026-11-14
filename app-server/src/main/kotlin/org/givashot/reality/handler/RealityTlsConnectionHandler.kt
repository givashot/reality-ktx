package org.givashot.reality.handler

import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.buffer.Unpooled
import io.netty.channel.*
import io.netty.handler.timeout.ReadTimeoutHandler
import io.netty.util.AttributeKey
import org.givashot.reality.CONNECTION_NUM_KEY
import org.givashot.reality.authentication.AuthResult
import org.givashot.reality.authentication.Authenticator
import org.givashot.reality.crypto.applyAuthKeySignature
import org.givashot.reality.fallback.FallbackHandlerFactory
import org.givashot.reality.fallback.HandshakeRecordProfile
import org.givashot.tls.ServerProfile
import org.givashot.tls.connection.TlsClientEvent
import org.givashot.tls.connection.TlsCommand
import org.givashot.tls.connection.TlsConnection
import org.givashot.tls.connection.TlsUsageException
import org.givashot.tls.handshake.EncryptedExtensionsData
import org.givashot.tls.state.TlsState
import org.slf4j.Logger
import org.slf4j.LoggerFactory

class RealityTlsConnectionHandler(
    private val authenticator: Authenticator,
    private val handshakeRecordProfile: HandshakeRecordProfile,
    private val fallbackHandlerFactory: FallbackHandlerFactory,
) : ChannelDuplexHandler(), TlsOuterEncryptionBypass {

    companion object {
        private const val IDLE_TIMEOUT_SECONDS = 300

        private val CLOSE_CAUSE_KEY = AttributeKey.valueOf<Throwable>("CLOSE_CAUSE_KEY")
    }

    private lateinit var logger: Logger

    private val tlsConnection = TlsConnection.create(
        ServerProfile(),
    )

    private var context: ChannelHandlerContext? = null
    private var initByteBuf: ByteBuf? = null
    private var authenticated = false
    private var switchedToFallback = false

    // Each direction leaves TLS on its own, irreversibly.
    private var inboundPassthrough = false
    private var outboundPassthrough = false
    private var readingTls = false

    override fun stopDecrypting() {
        logger.info("Stop decrypting called")
        if (inboundPassthrough) return
        inboundPassthrough = true
        // While records are being read, the read loop hands over the undecrypted rest once it unwinds.
        if (!readingTls) forwardUndecryptedInbound(checkNotNull(context))
    }

    override fun stopEncrypting() {
        logger.info("Stop encrypting called")
        outboundPassthrough = true
    }

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        context = ctx
        logger = LoggerFactory.getLogger("TlsConnectionHandler#${ctx.channel().attr(CONNECTION_NUM_KEY).get()}")
    }

    override fun channelRead(ctx: ChannelHandlerContext, input: Any) {
        if (input !is ByteBuf) {
            ctx.fireChannelRead(input)
            return
        }
        if (inboundPassthrough) {
            ctx.fireChannelRead(input)
            return
        }
        try {
            if (switchedToFallback || !input.isReadable) return

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

            tlsConnection.feed(bytes)
            readingTls = true
            try {
                while (!inboundPassthrough && !switchedToFallback) {
                    val event = tlsConnection.nextEvent() ?: break
                    handleClientEvent(ctx, event)
                    if (event is TlsClientEvent.ClientError || event is TlsClientEvent.ClientAlert) break
                }
            } finally {
                readingTls = false
            }
            if (inboundPassthrough) forwardUndecryptedInbound(ctx)
        } finally {
            input.release()
        }
    }

    override fun write(ctx: ChannelHandlerContext, output: Any, promise: ChannelPromise) {
        if (!outboundPassthrough && output is ByteBuf && tlsConnection.state == TlsState.Established) {
            try {
                val dump = ByteBufUtil.hexDump(
                    output, output.readerIndex(),
                    output.readableBytes().coerceAtMost(Int.MAX_VALUE)
                )
                logger.info("write outbound application bytes, size = ${output.readableBytes()}, dump_content = $dump")
                val bytes = ByteArray(output.readableBytes())
                output.getBytes(output.readerIndex(), bytes)
                val records = tlsConnection.execute(TlsCommand.SendApplicationData(bytes))
                val msg = Unpooled.wrappedBuffer(*records.toTypedArray())
                super.write(ctx, msg, promise)
            } finally {
                output.release()
            }
            return
        }
        super.write(ctx, output, promise)
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        logger.error("exception caught", cause)
        if (authenticated) {
            if (cause is TlsUsageException) {
                closeAfterWrite(
                    ctx,
                    writeOutbound(ctx, cause.replyAlertRecord),
                    cause.message,
                    cause
                )
            } else {
                close(ctx, "TLS connection handler failed", cause)
            }
        } else {
            switchToFallback(ctx, "TLS connection handler failed", cause)
        }
    }

    override fun close(ctx: ChannelHandlerContext, promise: ChannelPromise?) {
        logger.info("close called")
        // the proxy dest closed the connection
        if (!outboundPassthrough) {
            // we hold the outer tls connection, we should seed close notify
            val records = tlsConnection.execute(TlsCommand.Close)
            writeOutbound(ctx, *records.toTypedArray())
                .addListener {
                    super.close(ctx, promise)
                }
        } else {
            // we not hold tls connection, just close
            super.close(ctx, promise)
        }
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        logger.info("channelInactive called")
        tlsConnection.close(ctx.channel().attr(CLOSE_CAUSE_KEY).get())
        initByteBuf?.release()
        super.channelInactive(ctx)
    }

    private fun writeOutbound(ctx: ChannelHandlerContext, vararg records: ByteArray): ChannelFuture =
        if (outboundPassthrough) ctx.newSucceededFuture() else ctx.writeAndFlush(Unpooled.wrappedBuffer(*records))

    private fun close(ctx: ChannelHandlerContext, reason: String? = null, cause: Throwable? = null) {
        logger.info("manual close called with reason = $reason in TLS state ${tlsConnection.state}", cause)
        if (!ctx.channel().isActive) return
        ctx.channel().attr(CLOSE_CAUSE_KEY).set(cause)
        ctx.close()
    }

    private fun closeAfterWrite(
        ctx: ChannelHandlerContext,
        writeFuture: ChannelFuture,
        reason: String? = null,
        cause: Throwable? = null
    ) {
        writeFuture.addListener(ChannelFutureListener { close(ctx, reason, cause) })
    }

    private fun handleClientEvent(ctx: ChannelHandlerContext, event: TlsClientEvent) {
        logger.info("handleClientEvent called with event: ${event::class.simpleName}")
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

            TlsClientEvent.ClientFinished -> Unit

            is TlsClientEvent.ClientApplicationData -> {
                val dump = ByteBufUtil.hexDump(event.data, 0, event.data.size.coerceAtMost(Int.MAX_VALUE))
                logger.info("received inbound application bytes, size = ${event.data.size}, dump_content =  $dump")
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

    private fun sendServerFlight(ctx: ChannelHandlerContext, authKey: ByteArray) {
        logger.info("sendServerFlight called")
        val certificate = applyAuthKeySignature(authKey)
        val reply = tlsConnection.execute(
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
        tlsConnection.close(cause)
        logger.info("Switching unauthenticated connection to fallback: $reason", cause)
        val fallbackHandler = fallbackHandlerFactory.newForwardHandler(initByteBuf)
        val currentHandlerName = ctx.name()
        ctx.pipeline().apply {
            remove(ReadTimeoutHandler::class.java.simpleName)
            var foundCurrent = false
            val bizHandlerNames = names().filterNot { it.contains("TailContext") }
            for (name in bizHandlerNames) {
                if (foundCurrent) {
                    remove(name)
                }
                if (name == currentHandlerName) {
                    foundCurrent = true
                }
            }
            addAfter(ctx.name(), fallbackHandler::class.java.simpleName, fallbackHandler)
            remove(this@RealityTlsConnectionHandler)
        }
    }

    private fun forwardUndecryptedInbound(ctx: ChannelHandlerContext) {
        val rest = tlsConnection.drainUndecryptedInbound()
        if (rest.isNotEmpty()) {
            ctx.fireChannelRead(Unpooled.wrappedBuffer(rest))
        }
        logger.info(
            "forwardUndecryptedInbound called, rest.size = ${rest.size}, dump_content = ${
                ByteBufUtil.hexDump(rest, 0, rest.size.coerceAtMost(Int.MAX_VALUE))
            }"
        )
    }

}
