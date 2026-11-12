package org.givashot.reality.handler

import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.buffer.Unpooled
import io.netty.channel.*
import io.netty.channel.socket.SocketChannel
import io.netty.handler.timeout.IdleStateEvent
import io.netty.util.ReferenceCountUtil
import org.givashot.reality.CONNECTION_NUM_KEY
import org.givashot.reality.relay.BidiTcpRelaySession
import org.givashot.reality.relay.UpstreamChannelConnector
import org.givashot.reality.relay.UpstreamChannelHandler
import org.givashot.tunnel.vless.*
import org.givashot.tunnel.vless.const.VLESS_COMMAND_TYPE_TCP
import org.givashot.tunnel.vless.vision.VisionFrameCodec
import org.givashot.tunnel.vless.vision.VisionPaddingPolicy
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Handles the VLESS request on an authenticated TLS connection and relays it to the requested TCP target.
 * Sits after [RealityTlsConnectionHandler] in the pipeline: inbound, it receives decrypted client data; outbound,
 * it sees everything written towards the client.
 *
 * For the `xtls-rprx-vision` flow the client data is unpadded on the way to the target and the target data is padded
 * on the way to the client. Once either side's Vision stream ends with a direct-copy command, the outer TLS layer
 * is bypassed through [OuterEncryptionBypass], which therefore must be provided by a handler earlier in the pipeline.
 */
class VlessDuplexHandler(
    private val connectTimeoutMillis: Int = DEFAULT_CONNECT_TIMEOUT_MILLIS,
    private val maxPendingBytesPerDirection: Long = DEFAULT_MAX_PENDING_BYTES,
    private val flowPolicy: VlessFlowPolicy = VlessFlowPolicy(),
    private val visionPaddingPolicy: VisionPaddingPolicy = VisionPaddingPolicy.DEFAULT,
) : ChannelDuplexHandler() {

    companion object {
        const val DEFAULT_CONNECT_TIMEOUT_MILLIS = 5000
        const val DEFAULT_MAX_PENDING_BYTES = 1L shl 20
        private const val HEADER_TIMEOUT_MILLIS = 10_000L
        private const val MAX_HEADER_BYTES = 1024
    }

    private enum class Phase { WaitingHeader, Relaying, Closed }

    private lateinit var logger: Logger
    private var phase = Phase.WaitingHeader
    private var headerBuffer: ByteBuf? = null
    private var headerTimeout: ScheduledFuture<*>? = null
    private var session: BidiTcpRelaySession? = null
    private var connectFuture: ChannelFuture? = null
    private var frameCodec: VisionFrameCodec? = null
    private var bypass: OuterEncryptionBypass? = null
    private var directWriteSwitched = false
    private var directReadSwitched = false

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        logger = LoggerFactory.getLogger("VlessHandler#${ctx.channel().attr(CONNECTION_NUM_KEY).get()}")
    }

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
                if (relay == null) msg.release() else enqueueClientBytes(relay, msg)
            }

            Phase.Closed -> msg.release()
        }
    }

    /** Pads the data of the target for a Vision client; everything else is written as it is. */
    override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
        val frameCodec = this@VlessDuplexHandler.frameCodec
        if (msg !is ByteBuf
            || phase != Phase.Relaying
            || frameCodec == null
            || !frameCodec.serverEncoder.encoding
        ) {
            super.write(ctx, msg, promise)
            return
        }
        val bytes = ByteBufUtil.getBytes(msg)
        msg.release()

        val visionFrame = frameCodec.serverEncode(bytes)
        super.write(ctx, Unpooled.wrappedBuffer(visionFrame), promise)
        // The frames above were encrypted synchronously, so what follows may leave the outer TLS layer.
        if (!directWriteSwitched
            && !frameCodec.serverEncoder.encoding
            && frameCodec.serverEncoder.supportDirectRelay == true
        ) {
            directWriteSwitched = true
            bypass?.stopEncrypting()
        }
    }

    override fun channelWritabilityChanged(ctx: ChannelHandlerContext) {
        session?.downstreamWritabilityChanged()
        ctx.fireChannelWritabilityChanged()
    }

    override fun userEventTriggered(ctx: ChannelHandlerContext, evt: Any) {
        if (evt is IdleStateEvent) {
            val relay = session
            if (relay == null) ctx.close() else relay.failed("idle timeout")
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
            logger.warn("VLESS connection failed before relay started", cause)
            ctx.close()
        } else {
            relay.failed("VLESS relay failed", cause)
        }
    }

    private fun scheduleHeaderTimeout(ctx: ChannelHandlerContext) {
        if (headerTimeout != null) return
        headerTimeout = ctx.executor().schedule(
            {
                if (phase == Phase.WaitingHeader) {
                    rejectHeader(ctx, "VLESS request header was not received in time")
                }
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
            rejectHeader(ctx, "invalid VLESS request: ${failure.message}")
            return
        }

        when (result) {
            is VlessParseResult.NeedMoreData -> {
                if (buffer.readableBytes() > MAX_HEADER_BYTES) {
                    rejectHeader(ctx, "VLESS request header exceeds $MAX_HEADER_BYTES bytes")
                }
            }

            is VlessParseResult.Complete -> {
                logger.info("vless parse received: $result, uuid = ${String(result.header.uuid)}")
                val rejection = unsupportedReason(ctx, result.header)
                if (rejection != null) {
                    rejectHeader(ctx, rejection)
                    return
                }
                cancelHeaderTimeout()
                releaseHeaderBuffer()
                val initialPayload = Unpooled.wrappedBuffer(bytes, result.consumed, bytes.size - result.consumed)
                startRelay(ctx, result.header, initialPayload)
            }
        }
    }

    private fun unsupportedReason(ctx: ChannelHandlerContext, header: VlessRequestHeader): String? = when {
        header.command != VLESS_COMMAND_TYPE_TCP -> "unsupported VLESS command ${header.command}"
        header.port == 0 -> "VLESS target port must not be 0"
        header.host.isEmpty() -> "VLESS target host must not be empty"
        else -> flowPolicy.check(header)
            ?: if (header.decodedAddons.isVision && findBypass(ctx) == null) {
                "VLESS flow '${header.flow}' needs an outer TLS handler that can be bypassed"
            } else {
                null
            }
    }

    private fun findBypass(ctx: ChannelHandlerContext): OuterEncryptionBypass? =
        ctx.pipeline().firstNotNullOfOrNull { it.value as? OuterEncryptionBypass }

    /**
     * Forwards client data to the target. For Vision the frames are unpadded first, and a direct-copy command makes
     * the outer TLS layer pass up the rest of the client's stream as it is.
     */
    private fun enqueueClientBytes(relay: BidiTcpRelaySession, bytes: ByteBuf) {
        val frameCodec = frameCodec
        if (frameCodec == null || !frameCodec.decoder.decoding) {
            relay.enqueueDownstreamBytes(bytes)
            return
        }
        val raw = ByteBufUtil.getBytes(bytes)
        bytes.release()
        val content = frameCodec.decode(raw)
        relay.enqueueDownstreamBytes(Unpooled.wrappedBuffer(content))
        if (!directReadSwitched && frameCodec.decoder.directRelay) {
            directReadSwitched = true
            bypass?.stopDecrypting()
        }
    }

    private fun startRelay(ctx: ChannelHandlerContext, header: VlessRequestHeader, initialPayload: ByteBuf) {
        phase = Phase.Relaying
        val channel = ctx.channel()
        val relay = BidiTcpRelaySession(channel, maxPendingBytesPerDirection)
        session = relay

        if (header.decodedAddons.isVision) {
            frameCodec = VisionFrameCodec(header.uuid, visionPaddingPolicy)
            bypass = findBypass(ctx)
        }

        // Do not read client data until the target is connected and able to accept writes.
        channel.config().isAutoRead = false
        enqueueClientBytes(relay, initialPayload)

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
                sendResponseHeader(ctx, header, relay)
            } else {
                relay.failed("could not connect to VLESS target $target", future.cause())
            }
        }
    }

    /**
     * Sent once the target is connected and before any target data is relayed. Target reads only start
     * after the upstream channel becomes active, so the response header always precedes relayed data.
     */
    private fun sendResponseHeader(ctx: ChannelHandlerContext, header: VlessRequestHeader, relay: BidiTcpRelaySession) {
        if (relay.closed) return
        ctx.writeAndFlush(Unpooled.wrappedBuffer(VlessResponseHeader.encode(header.version)))
            .addListener { future ->
                if (!future.isSuccess) {
                    relay.failed("could not send VLESS response header", future.cause())
                }
            }
    }

    private fun rejectHeader(ctx: ChannelHandlerContext, reason: String) {
        logger.warn("Closing VLESS connection: $reason")
        phase = Phase.Closed
        cancelHeaderTimeout()
        releaseHeaderBuffer()
        ctx.close()
    }

    private fun releaseHeaderBuffer() {
        headerBuffer?.release()
        headerBuffer = null
    }
}
