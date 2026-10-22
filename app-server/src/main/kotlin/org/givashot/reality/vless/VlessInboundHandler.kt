package org.givashot.reality.vless

import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.socket.SocketChannel
import io.netty.handler.timeout.IdleStateEvent
import io.netty.util.ReferenceCountUtil
import org.givashot.reality.relay.BidiTcpRelaySession
import org.givashot.reality.relay.UpstreamChannelConnector
import org.givashot.reality.relay.UpstreamChannelHandler
import org.givashot.reality.tls.RealityTlsConnectionHandler
import org.givashot.tunnel.vless.VlessParseResult
import org.givashot.tunnel.vless.VlessProtocolException
import org.givashot.tunnel.vless.VlessRequestHeader
import org.givashot.tunnel.vless.VlessRequestParser
import org.givashot.tunnel.vless.VlessResponseHeader
import org.givashot.tunnel.vless.const.VLESS_COMMAND_TYPE_TCP
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.logging.Level
import java.util.logging.Logger

/**
 * Handles the VLESS request on an authenticated TLS connection and relays it to the requested TCP target.
 * Sits after [RealityTlsConnectionHandler] in the pipeline and receives decrypted application data from it.
 */
class VlessInboundHandler(
    private val tlsHandler: RealityTlsConnectionHandler,
    private val connectTimeoutMillis: Int = DEFAULT_CONNECT_TIMEOUT_MILLIS,
    private val maxPendingBytesPerDirection: Long = DEFAULT_MAX_PENDING_BYTES,
) : ChannelInboundHandlerAdapter() {

    private enum class Phase { WaitingHeader, Relaying, Closed }

    private var phase = Phase.WaitingHeader
    private var headerBuffer: ByteBuf? = null
    private var headerTimeout: ScheduledFuture<*>? = null
    private var session: BidiTcpRelaySession? = null
    private var connectFuture: ChannelFuture? = null

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (msg !is ByteBuf) {
            ReferenceCountUtil.release(msg)
            return
        }
        when (phase) {
            Phase.WaitingHeader -> {
                scheduleHeaderTimeout(ctx)
                onHeaderBytes(ctx, msg)
            }

            Phase.Relaying -> {
                val relay = session
                if (relay == null) msg.release() else relay.enqueueDownstreamBytes(msg)
            }

            Phase.Closed -> msg.release()
        }
    }

    override fun channelWritabilityChanged(ctx: ChannelHandlerContext) {
        session?.downstreamWritabilityChanged()
        ctx.fireChannelWritabilityChanged()
    }

    override fun userEventTriggered(ctx: ChannelHandlerContext, evt: Any) {
        if (evt is IdleStateEvent) {
            val relay = session
            if (relay == null) tlsHandler.closeWithCloseNotify() else relay.failed("idle timeout")
        } else {
            ctx.fireUserEventTriggered(evt)
        }
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        phase = Phase.Closed
        cancelHeaderTimeout()
        releaseHeaderBuffer()
        connectFuture?.takeIf { it.isCancellable }?.cancel(false)
        session?.downstreamClosed()
        ctx.fireChannelInactive()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        val relay = session
        if (relay == null) {
            logger.log(Level.WARNING, "VLESS connection failed before relay started", cause)
            ctx.close()
        } else {
            relay.failed("VLESS relay failed", cause)
        }
    }

    private fun scheduleHeaderTimeout(ctx: ChannelHandlerContext) {
        if (headerTimeout != null) return
        headerTimeout = ctx.executor().schedule(
            Runnable {
                if (phase == Phase.WaitingHeader) rejectHeader("VLESS request header was not received in time")
            },
            HEADER_TIMEOUT_MILLIS,
            TimeUnit.MILLISECONDS,
        )
    }

    private fun cancelHeaderTimeout() {
        headerTimeout?.cancel(false)
        headerTimeout = null
    }

    private fun onHeaderBytes(ctx: ChannelHandlerContext, msg: ByteBuf) {
        val buffer = headerBuffer ?: ctx.alloc().buffer().also { headerBuffer = it }
        buffer.writeBytes(msg)
        msg.release()

        val bytes = ByteArray(buffer.readableBytes())
        buffer.getBytes(buffer.readerIndex(), bytes)
        val result = try {
            VlessRequestParser.parse(bytes)
        } catch (failure: VlessProtocolException) {
            rejectHeader("invalid VLESS request: ${failure.message}")
            return
        }

        when (result) {
            is VlessParseResult.NeedMoreData -> {
                if (buffer.readableBytes() > MAX_HEADER_BYTES) {
                    rejectHeader("VLESS request header exceeds $MAX_HEADER_BYTES bytes")
                }
            }

            is VlessParseResult.Complete -> {
                val rejection = unsupportedReason(result.header)
                if (rejection != null) {
                    rejectHeader(rejection)
                    return
                }
                cancelHeaderTimeout()
                releaseHeaderBuffer()
                val initialPayload = Unpooled.wrappedBuffer(bytes, result.consumed, bytes.size - result.consumed)
                startRelay(ctx, result.header, initialPayload)
            }
        }
    }

    private fun unsupportedReason(header: VlessRequestHeader): String? = when {
        header.command != VLESS_COMMAND_TYPE_TCP -> "unsupported VLESS command ${header.command}"
        header.port == 0 -> "VLESS target port must not be 0"
        header.host.isEmpty() -> "VLESS target host must not be empty"
        else -> null
    }

    private fun startRelay(ctx: ChannelHandlerContext, header: VlessRequestHeader, initialPayload: ByteBuf) {
        phase = Phase.Relaying
        val channel = ctx.channel()
        val relay = BidiTcpRelaySession(TlsRelayDownstream(channel, tlsHandler), maxPendingBytesPerDirection)
        session = relay

        // Do not read client data until the target is connected and able to accept writes.
        channel.config().isAutoRead = false
        relay.enqueueDownstreamBytes(initialPayload)

        val target = "${header.host}:${header.port}"
        connectFuture = UpstreamChannelConnector.connect(
            channel.eventLoop(),
            object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(peerChannel: SocketChannel) {
                    peerChannel.config().isAutoRead = false
                    peerChannel.pipeline().addLast(UpstreamChannelHandler(relay))
                }
            },
            header.host,
            header.port,
            connectTimeoutMillis,
        ).addListener { future ->
            if (future.isSuccess) {
                sendResponseHeader(header, relay)
            } else {
                relay.failed("could not connect to VLESS target $target", future.cause())
            }
        }
    }

    /**
     * Sent once the target is connected and before any target data is relayed. Target reads only start
     * after the upstream channel becomes active, so the response header always precedes relayed data.
     */
    private fun sendResponseHeader(header: VlessRequestHeader, relay: BidiTcpRelaySession) {
        if (relay.closed) return
        tlsHandler.writeApplicationData(Unpooled.wrappedBuffer(VlessResponseHeader.encode(header.version)))
            .addListener { future ->
                if (!future.isSuccess) relay.failed("could not send VLESS response header", future.cause())
            }
    }

    private fun rejectHeader(reason: String) {
        logger.warning("Closing VLESS connection: $reason")
        phase = Phase.Closed
        cancelHeaderTimeout()
        releaseHeaderBuffer()
        tlsHandler.closeWithCloseNotify()
    }

    private fun releaseHeaderBuffer() {
        headerBuffer?.release()
        headerBuffer = null
    }

    companion object {
        private val logger = Logger.getLogger(VlessInboundHandler::class.java.name)

        const val DEFAULT_CONNECT_TIMEOUT_MILLIS = 5000
        const val DEFAULT_MAX_PENDING_BYTES = 1L shl 20
        private const val HEADER_TIMEOUT_MILLIS = 10_000L
        private const val MAX_HEADER_BYTES = 1024
    }
}
