package org.givashot.reality.fallback

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.socket.SocketChannel
import io.netty.util.ReferenceCountUtil
import org.givashot.reality.relay.TcpRelaySession
import org.givashot.reality.relay.UpstreamChannelConnector
import org.givashot.reality.relay.UpstreamChannelHandler
import org.slf4j.LoggerFactory

class FallbackChannelInboundHandler(
    private val upstreamHost: String,
    private val upstreamPort: Int,
    private val connectTimeoutMillis: Int,
    private val maxPendingBytesPerDirection: Long,
    private val initialBytes: ByteBuf?,
) : ChannelInboundHandlerAdapter() {

    var tcpRelaySession: TcpRelaySession? = null
    var connectFuture: ChannelFuture? = null

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        val tcpRelaySession =
            TcpRelaySession(ctx.channel(), maxPendingBytesPerDirection)
        this.tcpRelaySession = tcpRelaySession

        // Do not read downstream data until the upstream is connected and able to accept writes.
        ctx.channel().config().isAutoRead = false
        if (initialBytes != null) {
            tcpRelaySession.enqueueDownstreamBytes(initialBytes)
        }
        connectFuture = UpstreamChannelConnector.connect(
            ctx.channel().eventLoop(),
            object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(peerChannel: SocketChannel) {
                    peerChannel.config().isAutoRead = false
                    peerChannel.pipeline().addLast(UpstreamChannelHandler(tcpRelaySession))
                }
            },
            upstreamHost,
            upstreamPort,
            connectTimeoutMillis
        ).addListener { future ->
            if (!future.isSuccess) {
                tcpRelaySession.failed(
                    "could not connect to fallback ${upstreamHost}:${upstreamPort}",
                    future.cause(),
                )
            }
        }
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (msg is ByteBuf && tcpRelaySession != null) {
            tcpRelaySession!!.enqueueDownstreamBytes(msg)
        } else {
            ReferenceCountUtil.release(msg)
        }
    }

    override fun channelWritabilityChanged(ctx: ChannelHandlerContext) {
        tcpRelaySession?.downstreamWritabilityChanged()
        ctx.fireChannelWritabilityChanged()
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        connectFuture?.takeIf { it.isCancellable }?.cancel(false)
        tcpRelaySession?.downstreamClosed()
        ctx.fireChannelInactive()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        tcpRelaySession?.failed("fallback client channel failed", cause)
            ?: logger.warn("Fallback client channel failed", cause)
        ctx.close()
    }

    companion object {
        private val logger = LoggerFactory.getLogger(FallbackChannelInboundHandler::class.java)
    }
}