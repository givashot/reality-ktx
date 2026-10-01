package org.givashot.reality.fallback

import io.netty.buffer.ByteBuf
import io.netty.channel.Channel
import java.util.*
import java.util.logging.Level
import java.util.logging.Logger

class BidiTcpRelaySession(
    private val downstreamChannel: Channel,
    private val maxPendingBytesPerDirection: Long,
) {

    private data class PendingDownstreamWrite(val bytes: ByteBuf, val size: Int)

    private val pendingDownstreamWrites = ArrayDeque<PendingDownstreamWrite>()
    private var upstreamChannel: Channel? = null
    private var downToUpPendingBytes = 0L
    private var upToDownPendingBytes = 0L
    var closed: Boolean = false
        private set

    fun enqueueDownstreamBytes(bytes: ByteBuf) {
        if (!bytes.isReadable) {
            bytes.release()
            return
        }
        if (closed) {
            bytes.release()
            return
        }

        val size = bytes.readableBytes()
        if (!reserveDownToUpBytes(size)) {
            bytes.release()
            failPendingLimit("down-to-up")
            return
        }

        val target = upstreamChannel
        if (target == null || !target.isActive) {
            pendingDownstreamWrites.addLast(PendingDownstreamWrite(bytes, size))
            updateReadState()
        } else {
            writeToUpFromDown(target, bytes, size, flush = true)
        }
    }

    fun enqueueUpstreamBytes(bytes: ByteBuf) {
        if (!bytes.isReadable) {
            bytes.release()
            return
        }
        if (closed) {
            bytes.release()
            return
        }

        val size = bytes.readableBytes()
        if (!reserveUpToDownBytes(size)) {
            bytes.release()
            failPendingLimit("up-to-down")
            return
        }
        writeToDownFromUp(bytes, size)
    }

    fun upstreamConnected(upstream: Channel) {
        if (closed) {
            upstream.close()
            return
        }
        upstreamChannel = upstream
        drainDownstreamWrites()
        updateReadState()
    }

    fun downstreamWritabilityChanged() {
        updateReadState()
    }

    fun upstreamWritabilityChanged() {
        drainDownstreamWrites()
        updateReadState()
    }

    fun failed(reason: String, cause: Throwable? = null) {
        if (closed) return
        closed = true
        releasePendingDownstreamWrites()
        if (cause == null) logger.warning("Closing fallback connection: $reason")
        else logger.log(Level.WARNING, "Closing fallback connection: $reason", cause)
        closeChannels()
    }

    fun downstreamClosed() {
        if (closed) return
        closed = true
        releasePendingDownstreamWrites()
        closeChannels()
    }

    fun upstreamClosed() {
        if (closed) return
        closed = true
        releasePendingDownstreamWrites()
        if (downstreamChannel.isActive) downstreamChannel.close()
    }

    private fun drainDownstreamWrites() {
        val target = upstreamChannel ?: return
        if (closed || !target.isActive || !target.isWritable) return

        while (pendingDownstreamWrites.isNotEmpty() && target.isActive && target.isWritable) {
            val pending = pendingDownstreamWrites.removeFirst()
            writeToUpFromDown(target, pending.bytes, pending.size, flush = false)
        }
        if (target.isActive) target.flush()
    }

    private fun writeToUpFromDown(target: Channel, bytes: ByteBuf, size: Int, flush: Boolean) {
        val future = if (flush) target.writeAndFlush(bytes) else target.write(bytes)
        updateReadState()
        future.addListener { writeFuture ->
            downToUpPendingBytes -= size.toLong()
            if (!writeFuture.isSuccess) {
                failed("writing downstream data to fallback upstream failed", writeFuture.cause())
            } else {
                updateReadState()
            }
        }
    }

    private fun writeToDownFromUp(bytes: ByteBuf, size: Int) {
        val future = downstreamChannel.writeAndFlush(bytes)
        updateReadState()
        future.addListener { writeFuture ->
            upToDownPendingBytes -= size.toLong()
            if (!writeFuture.isSuccess) {
                failed("writing fallback upstream data to downstream failed", writeFuture.cause())
            } else {
                updateReadState()
            }
        }
    }

    private fun reserveDownToUpBytes(size: Int): Boolean {
        if (size.toLong() > maxPendingBytesPerDirection - downToUpPendingBytes) return false
        downToUpPendingBytes += size.toLong()
        return true
    }

    private fun reserveUpToDownBytes(size: Int): Boolean {
        if (size.toLong() > maxPendingBytesPerDirection - upToDownPendingBytes) return false
        upToDownPendingBytes += size.toLong()
        return true
    }

    private fun updateReadState() {
        if (closed) {
            setAutoRead(downstreamChannel, false)
            upstreamChannel?.let { setAutoRead(it, false) }
            return
        }

        val upstream = upstreamChannel
        setAutoRead(
            downstreamChannel,
            upstream != null &&
                    upstream.isActive &&
                    upstream.isWritable &&
                    downToUpPendingBytes < maxPendingBytesPerDirection,
        )
        upstream?.let {
            setAutoRead(
                it,
                downstreamChannel.isActive &&
                        downstreamChannel.isWritable &&
                        upToDownPendingBytes < maxPendingBytesPerDirection,
            )
        }
    }

    private fun setAutoRead(channel: Channel, enabled: Boolean) {
        if (channel.config().isAutoRead != enabled) {
            channel.config().isAutoRead = enabled
        }
    }

    private fun releasePendingDownstreamWrites() {
        while (pendingDownstreamWrites.isNotEmpty()) {
            val pending = pendingDownstreamWrites.removeFirst()
            downToUpPendingBytes -= pending.size.toLong()
            pending.bytes.release()
        }
    }

    private fun closeChannels() {
        setAutoRead(downstreamChannel, false)
        if (downstreamChannel.isActive) downstreamChannel.close()
        upstreamChannel?.let {
            setAutoRead(it, false)
            if (it.isActive) it.close()
        }
    }

    private fun failPendingLimit(direction: String) {
        failed(
            "pending bytes exceeded $maxPendingBytesPerDirection-byte limit ($direction)",
        )
    }

    companion object {
        private val logger = Logger.getLogger(BidiTcpRelaySession::class.java.name)
    }
}