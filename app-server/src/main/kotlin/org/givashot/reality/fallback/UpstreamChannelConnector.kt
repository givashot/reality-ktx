package org.givashot.reality.fallback

import io.netty.bootstrap.Bootstrap
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelHandler
import io.netty.channel.ChannelOption
import io.netty.channel.EventLoopGroup
import io.netty.channel.socket.nio.NioSocketChannel

object UpstreamChannelConnector {

    fun connect(
        eventGroup: EventLoopGroup,
        handler: ChannelHandler,
        host: String,
        port: Int,
        connectTimeoutMillis: Int,
    ): ChannelFuture {
        return Bootstrap()
            .group(eventGroup)
            .channel(NioSocketChannel::class.java)
            .option(
                ChannelOption.CONNECT_TIMEOUT_MILLIS,
                connectTimeoutMillis
            )
            .handler(handler)
            .connect(host, port)
    }

}