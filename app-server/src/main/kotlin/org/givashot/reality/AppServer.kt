package org.givashot.reality

import io.netty.bootstrap.ServerBootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelInitializer
import io.netty.channel.MultiThreadIoEventLoopGroup
import io.netty.channel.nio.NioIoHandler
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.timeout.ReadTimeoutHandler
import org.givashot.reality.authentication.Authenticator
import org.givashot.reality.config.loadAppConfig
import org.givashot.reality.fallback.FallbackHandlerFactory
import org.givashot.reality.tls.FallbackHandshakeRecordModel
import org.givashot.reality.tls.RealityTlsConnectionHandler

fun main() {
    val config = loadAppConfig()
    val boss = MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory())
    val workers = MultiThreadIoEventLoopGroup(0, NioIoHandler.newFactory())
    try {
        val authenticator = Authenticator(
            config.server.reality
        )
        val handshakeRecordProfile = FallbackHandshakeRecordModel(config.server.reality.fallbackDest, workers).learn()
        val fallbackHandlerFactory = FallbackHandlerFactory(
            fallbackDest = config.server.reality.fallbackDest
        )
        val server: Channel = ServerBootstrap()
            .group(boss, workers)
            .channel(NioServerSocketChannel::class.java)
            .childHandler(object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(ch: SocketChannel) {
                    ch.pipeline().addLast(ReadTimeoutHandler(10))
                    ch.pipeline().addLast(
                        RealityTlsConnectionHandler(
                            authenticator = authenticator,
                            handshakeRecordProfile = handshakeRecordProfile,
                            fallbackHandlerFactory = fallbackHandlerFactory,
                        )
                    )
                }
            })
            .bind(config.server.port)
            .sync()
            .channel()
        println("started server")
        server.closeFuture().sync()
    } finally {
        boss.shutdownGracefully()
        workers.shutdownGracefully()
    }
}
