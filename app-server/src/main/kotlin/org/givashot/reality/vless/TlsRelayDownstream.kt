package org.givashot.reality.vless

import io.netty.buffer.ByteBuf
import io.netty.channel.Channel
import io.netty.channel.ChannelFuture
import org.givashot.reality.relay.RelayDownstream
import org.givashot.reality.tls.RealityTlsConnectionHandler

class TlsRelayDownstream(
    private val channel: Channel,
    private val tlsHandler: RealityTlsConnectionHandler,
) : RelayDownstream {

    override val isActive: Boolean
        get() = channel.isActive

    override val isWritable: Boolean
        get() = channel.isWritable

    override var autoRead: Boolean
        get() = channel.config().isAutoRead
        set(value) {
            channel.config().isAutoRead = value
        }

    override fun writeAndFlush(bytes: ByteBuf): ChannelFuture = tlsHandler.writeApplicationData(bytes)

    override fun close() {
        tlsHandler.closeWithCloseNotify()
    }
}
