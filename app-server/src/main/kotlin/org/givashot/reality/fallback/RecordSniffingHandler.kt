package org.givashot.reality.fallback

import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import org.givashot.tls.constant.TLS_CONTENT_TYPE_APPLICATION_DATA
import org.givashot.tls.constant.TLS_CONTENT_TYPE_HANDSHAKE
import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE_SERVER_HELLO
import org.givashot.tls.handshake.HandshakeMessageDecoder
import org.givashot.tls.handshake.parseServerHello
import org.givashot.tls.record.TlsRecordDecoder
import org.givashot.tls.record.TlsRecordMessage

/**
 * Passively observes the TLS records of a connection without consuming or modifying any bytes.
 *
 * Captures the ServerHello extension order and the length of every inbound 0x17 record received
 * before the first outbound 0x17 record (our own Finished) is written.
 */
internal class RecordSniffingHandler : ChannelDuplexHandler() {

    private val inboundDecoder = TlsRecordDecoder()
    private val outboundDecoder = TlsRecordDecoder()
    private val handshakeDecoder = HandshakeMessageDecoder()
    private val applicationDataLengths = mutableListOf<Int>()

    @Volatile
    var serverHelloExtensionOrder: List<Int>? = null
        private set

    @Volatile
    private var capturingDone = false

    val applicationDataRecordLengths: List<Int>
        get() = applicationDataLengths.toList()

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (!capturingDone && msg is ByteBuf) {
            sniff { inboundDecoder.feed(ByteBufUtil.getBytes(msg)).forEach(::onInboundRecord) }
        }
        ctx.fireChannelRead(msg)
    }

    override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
        if (!capturingDone && msg is ByteBuf) {
            sniff {
                val records = outboundDecoder.feed(ByteBufUtil.getBytes(msg))
                if (records.any { it.contentType == TLS_CONTENT_TYPE_APPLICATION_DATA }) capturingDone = true
            }
        }
        ctx.write(msg, promise)
    }

    private fun onInboundRecord(record: TlsRecordMessage) {
        when (record.contentType) {
            TLS_CONTENT_TYPE_APPLICATION_DATA -> applicationDataLengths += record.payload.size
            TLS_CONTENT_TYPE_HANDSHAKE -> if (serverHelloExtensionOrder == null) onHandshakeFragment(record.payload)
        }
    }

    private fun onHandshakeFragment(fragment: ByteArray) {
        val serverHello = handshakeDecoder.feed(fragment)
            .firstOrNull { it.type == TLS_HANDSHAKE_CONTENT_TYPE_SERVER_HELLO }
            ?: return
        serverHelloExtensionOrder = serverHello.parseServerHello().extensionOrder
        handshakeDecoder.reset()
    }

    // Non-TLS or malformed bytes end the sniffing; the pipeline itself must never be affected.
    private inline fun sniff(action: () -> Unit) {
        try {
            action()
        } catch (_: Exception) {
            capturingDone = true
        }
    }
}
