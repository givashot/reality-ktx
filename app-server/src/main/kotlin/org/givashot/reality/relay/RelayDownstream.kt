package org.givashot.reality.relay

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelFuture

/** The client-facing side of a relay. Writes are framed however the connection requires. */
interface RelayDownstream {
    val isActive: Boolean
    val isWritable: Boolean
    var autoRead: Boolean

    /** Takes ownership of [bytes]. */
    fun writeAndFlush(bytes: ByteBuf): ChannelFuture

    fun close()
}
