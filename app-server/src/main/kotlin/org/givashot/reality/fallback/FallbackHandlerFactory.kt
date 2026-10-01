package org.givashot.reality.fallback

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandler
import org.givashot.reality.config.RealityConfig

class FallbackHandlerFactory(
    private val fallbackDest: RealityConfig.FallbackDest,
    private val connectTimeoutMillis: Int = 5_000,
    private val maxPendingBytesPerDirection: Long = DEFAULT_MAX_PENDING_BYTES,
) {
    init {
        require(maxPendingBytesPerDirection > 0) { "maxPendingBytes must be positive" }
    }

    fun newForwardHandler(initialBytes: ByteBuf? = null): ChannelHandler =
        DownstreamChannelHandler(
            fallbackDest.host,
            fallbackDest.port,
            connectTimeoutMillis,
            maxPendingBytesPerDirection,
            initialBytes
        )

    companion object {
        const val DEFAULT_MAX_PENDING_BYTES: Long = 1L shl 20
    }

}


