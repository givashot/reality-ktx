package org.givashot.reality.fallback

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.util.ReferenceCountUtil

class UpstreamChannelHandler(private val bidiTcpRelaySession: BidiTcpRelaySession) : ChannelInboundHandlerAdapter() {

    override fun channelActive(ctx: ChannelHandlerContext) {
        bidiTcpRelaySession.upstreamConnected(ctx.channel())
        ctx.fireChannelActive()
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (msg is ByteBuf) bidiTcpRelaySession.enqueueUpstreamBytes(msg)
        else ReferenceCountUtil.release(msg)
    }

    override fun channelWritabilityChanged(ctx: ChannelHandlerContext) {
        bidiTcpRelaySession.upstreamWritabilityChanged()
        ctx.fireChannelWritabilityChanged()
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        bidiTcpRelaySession.upstreamClosed()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        bidiTcpRelaySession.failed("fallback peer channel failed", cause)
        ctx.close()
    }

}