package org.givashot.reality

import io.netty.bootstrap.ServerBootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelInitializer
import io.netty.channel.MultiThreadIoEventLoopGroup
import io.netty.channel.nio.NioIoHandler
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.timeout.ReadTimeoutHandler
import io.netty.util.AttributeKey
import org.givashot.reality.authentication.Authenticator
import org.givashot.reality.config.loadAppConfig
import org.givashot.reality.handler.LoggerHandler
import org.givashot.reality.handler.RealityTlsConnectionHandler
import org.givashot.reality.fallback.FallbackHandlerFactory
import org.givashot.reality.fallback.FallbackHandshakeRecordModel
import org.givashot.reality.handler.VlessDuplexHandler
import org.slf4j.LoggerFactory
import java.util.concurrent.atomic.AtomicInteger

private val logger = LoggerFactory.getLogger("org.givashot.reality.AppServer")

val CONNECTION_NUM_KEY: AttributeKey<Int> = AttributeKey.valueOf("CONNECTION_NUM_KEY")

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
        val connectionNum = AtomicInteger()
        val server: Channel = ServerBootstrap()
            .group(boss, workers)
            .channel(NioServerSocketChannel::class.java)
            .childHandler(object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(ch: SocketChannel) {
                    ch.pipeline().channel().attr(CONNECTION_NUM_KEY).set(connectionNum.incrementAndGet())
                    ch.pipeline().addLast(ReadTimeoutHandler::class.java.simpleName, ReadTimeoutHandler(10))
                    ch.pipeline().addLast(LoggerHandler::class.java.simpleName, LoggerHandler())
                    ch.pipeline().addLast(
                        RealityTlsConnectionHandler::class.java.simpleName, RealityTlsConnectionHandler(
                            authenticator = authenticator,
                            handshakeRecordProfile = handshakeRecordProfile,
                            fallbackHandlerFactory = fallbackHandlerFactory,
                        )
                    )
                    ch.pipeline().addLast(VlessDuplexHandler::class.java.simpleName, VlessDuplexHandler())
                }
            })
            .bind(config.server.port)
            .sync()
            .channel()
        logger.info(
            "Reality server started on port {}, " +
                    "\n config = {}" +
                    "\n handshakeRecordProfile = {}",
            config.server.port,
            config,
            handshakeRecordProfile
        )
        server.closeFuture().sync()
    } finally {
        boss.shutdownGracefully()
        workers.shutdownGracefully()
    }
}
