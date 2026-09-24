package org.givashot.reality.fallback

import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBuf
import io.netty.channel.*
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.util.ReferenceCountUtil
import org.givashot.reality.config.RealityConfig
import java.net.InetSocketAddress
import java.util.*

class FallbackService(
    private val fallbackDest: RealityConfig.FallbackDest,
    private val connectTimeoutMillis: Int = 5_000,
) {
    fun newForwardHandler(initialBytes: ByteBuf? = null): ChannelHandler =
        FallbackHandler(fallbackDest, connectTimeoutMillis, initialBytes)
}

class FallbackHandler internal constructor(
    private val fallbackDest: RealityConfig.FallbackDest,
    private val connectTimeoutMillis: Int,
    private val initialBytes: ByteBuf? = null
) : ChannelInboundHandlerAdapter() {
    private var bridge: FallbackBridge? = null

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        val clientChannel = ctx.channel()
        val bridge = FallbackBridge(clientChannel).also { this.bridge = it }

        // 关键点修复：在对端未连接成功前暂停客户端读，防止背压失效导致的 OOM
        clientChannel.config().isAutoRead = false

        if (initialBytes != null) {
            bridge.enqueue(initialBytes)
        }

        Bootstrap()
            .group(clientChannel.eventLoop())
            .channel(NioSocketChannel::class.java)
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeoutMillis)
            .handler(object : ChannelInitializer<SocketChannel>() {
                override fun initChannel(ch: SocketChannel) {
                    ch.pipeline().addLast(PeerToClientHandler(bridge))
                }
            })
            .connect(InetSocketAddress(fallbackDest.host, fallbackDest.port))
            .addListener { future ->
                if (!future.isSuccess) {
                    bridge.failed()
                }
            }
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        val bridge = this.bridge
        if (msg is ByteBuf && bridge != null) {
            bridge.enqueue(msg)
        } else {
            ReferenceCountUtil.release(msg)
        }
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        bridge?.clientClosed()
        ctx.fireChannelInactive()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        bridge?.failed()
        ctx.close()
    }
}

internal class FallbackBridge(
    val client: Channel,
) {
    private val pending = ArrayDeque<ByteBuf>()
    private var peer: Channel? = null

    fun enqueue(bytes: ByteBuf) {
        if (!bytes.isReadable) {
            bytes.release()
            return
        }

        val target = peer
        if (target != null && target.isActive) {
            target.writeAndFlush(bytes)
        } else {
            pending.addLast(bytes)
        }
    }

    fun connected(target: Channel) {
        peer = target
        while (pending.isNotEmpty() && target.isActive) {
            target.write(pending.removeFirst())
        }
        if (target.isActive) {
            target.flush()
        }
        // 关键点修复：连接建立且清空 Pending 后恢复客户端读取
        client.config().isAutoRead = true
    }

    fun failed() {
        releasePending()
        if (client.isActive) client.close()
    }

    fun clientClosed() {
        releasePending()
        peer?.let { if (it.isActive) it.close() }
    }

    fun peerClosed() {
        releasePending()
        if (client.isActive) client.close()
    }

    private fun releasePending() {
        while (pending.isNotEmpty()) {
            pending.removeFirst().release()
        }
    }
}

private class PeerToClientHandler(
    private val bridge: FallbackBridge,
) : ChannelInboundHandlerAdapter() {
    override fun channelActive(ctx: ChannelHandlerContext) {
        bridge.connected(ctx.channel())
        ctx.fireChannelActive()
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (msg is ByteBuf && bridge.client.isActive) {
            bridge.client.writeAndFlush(msg)
        } else {
            ReferenceCountUtil.release(msg)
        }
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        bridge.peerClosed()
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        bridge.peerClosed()
        ctx.close()
    }
}
