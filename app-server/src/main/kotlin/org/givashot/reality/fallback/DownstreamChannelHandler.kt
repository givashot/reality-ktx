package org.givashot.reality.fallback

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.socket.SocketChannel
import io.netty.util.ReferenceCountUtil
import java.util.logging.Level
import java.util.logging.Logger

class DownstreamChannelHandler(
    private val upstreamHost: String,
    private val upstreamPort: Int,
    private val connectTimeoutMillis: Int,
    private val maxPendingBytesPerDirection: Long,
    private val initialBytes: ByteBuf?,
) : ChannelInboundHandlerAdapter() {

    var bidiTcpRelaySession: BidiTcpRelaySession? = null
    var connectFuture: ChannelFuture? = null

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        val bidiTcpRelaySession = BidiTcpRelaySession(ctx.channel(), maxPendingBytesPerDirection)
        this.bidiTcpRelaySession = bidiTcpRelaySession

        // Do not read downstream data until the upstream is connected and able to accept writes.
        ctx.channel().config().isAutoRead = false
        if (initialBytes != null) {
            bidiTcpRelaySession.enqueueDownstreamBytes(initialBytes)
        }
        connectFuture = UpstreamChannelConnector.connect(
            ctx.channel().eventLoop(),
            object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(peerChannel: SocketChannel) {
                    peerChannel.config().isAutoRead = false
                    peerChannel.pipeline().addLast(UpstreamChannelHandler(bidiTcpRelaySession))
                }
            },
            upstreamHost,
            upstreamPort,
            connectTimeoutMillis
        ).addListener { future ->
            if (!future.isSuccess) {
                bidiTcpRelaySession.failed(
                    "could not connect to fallback ${upstreamHost}:${upstreamPort}",
                    future.cause(),
                )
            }
        }
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (msg is ByteBuf && bidiTcpRelaySession != null) {
            bidiTcpRelaySession!!.enqueueDownstreamBytes(msg)
        } else {
            ReferenceCountUtil.release(msg)
        }
    }

    override fun channelWritabilityChanged(ctx: ChannelHandlerContext) {
        bidiTcpRelaySession?.downstreamWritabilityChanged()
        ctx.fireChannelWritabilityChanged()
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        connectFuture?.takeIf { it.isCancellable }?.cancel(false)
        bidiTcpRelaySession?.downstreamClosed()
        ctx.fireChannelInactive()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        bidiTcpRelaySession?.failed("fallback client channel failed", cause)
            ?: logger.log(Level.WARNING, "Fallback client channel failed", cause)
        ctx.close()
    }

    companion object {
        private val logger = Logger.getLogger(DownstreamChannelHandler::class.java.name)
    }
}