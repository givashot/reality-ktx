package org.givashot.reality.fallback

import io.netty.buffer.ByteBuf
import io.netty.channel.Channel
import io.netty.channel.ChannelFuture
import org.givashot.reality.relay.RelayDownstream

class ChannelRelayDownstream(private val channel: Channel) : RelayDownstream {

    override val isActive: Boolean
        get() = channel.isActive

    override val isWritable: Boolean
        get() = channel.isWritable

    override var autoRead: Boolean
        get() = channel.config().isAutoRead
        set(value) {
            channel.config().isAutoRead = value
        }

    override fun writeAndFlush(bytes: ByteBuf): ChannelFuture = channel.writeAndFlush(bytes)

    override fun close() {
        channel.close()
    }
}
