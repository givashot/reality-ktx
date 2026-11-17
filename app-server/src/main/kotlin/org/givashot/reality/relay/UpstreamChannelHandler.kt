package org.givashot.reality.relay

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.util.ReferenceCountUtil

class UpstreamChannelHandler(private val tcpRelaySession: TcpRelaySession) : ChannelInboundHandlerAdapter() {

    override fun channelActive(ctx: ChannelHandlerContext) {
        tcpRelaySession.upstreamConnected(ctx.channel())
        ctx.fireChannelActive()
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (msg is ByteBuf) tcpRelaySession.enqueueUpstreamBytes(msg)
        else ReferenceCountUtil.release(msg)
    }

    override fun channelWritabilityChanged(ctx: ChannelHandlerContext) {
        tcpRelaySession.upstreamWritabilityChanged()
        ctx.fireChannelWritabilityChanged()
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        tcpRelaySession.upstreamClosed()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        tcpRelaySession.failed("fallback peer channel failed", cause)
        ctx.close()
    }

}