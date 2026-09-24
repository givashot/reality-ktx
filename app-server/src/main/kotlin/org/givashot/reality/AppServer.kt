package org.givashot.reality

import io.netty.bootstrap.ServerBootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelInitializer
import io.netty.channel.MultiThreadIoEventLoopGroup
import io.netty.channel.nio.NioIoHandler
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.timeout.ReadTimeoutHandler
import org.givashot.reality.authentication.AuthenticationHandler
import org.givashot.reality.authentication.Authenticator
import org.givashot.reality.config.loadAppConfig
import org.givashot.reality.fallback.FallbackService
import org.givashot.reality.manager.connection.ConnectionManager
import org.givashot.reality.tls.FallbackHandshakeRecordModel
import org.givashot.reality.tls.RealityTLSHandshakeService

fun main() {
    val config = loadAppConfig()
    val boss = MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory())
    val workers = MultiThreadIoEventLoopGroup(0, NioIoHandler.newFactory())
    try {
        val authenticator = Authenticator(
            config.server.reality
        )
        val handshakeRecordProfile = FallbackHandshakeRecordModel(config.server.reality.fallbackDest, workers).learn()
        val connectionManager = ConnectionManager(
            tlsHandshakeService = RealityTLSHandshakeService(handshakeRecordProfile),
        )
        val fallbackService = FallbackService(
            fallbackDest = config.server.reality.fallbackDest
        )
        val server: Channel = ServerBootstrap()
            .group(boss, workers)
            .channel(NioServerSocketChannel::class.java)
            .childHandler(object : ChannelInitializer<io.netty.channel.socket.SocketChannel>() {
                override fun initChannel(ch: io.netty.channel.socket.SocketChannel) {
                    ch.pipeline().addLast(ReadTimeoutHandler(10))
                    ch.pipeline().addLast(AuthenticationHandler(authenticator, connectionManager, fallbackService))
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
