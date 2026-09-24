package org.givashot.reality.tls

import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelPromise
import io.netty.channel.EventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import org.givashot.reality.config.RealityConfig
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import javax.net.ssl.SNIHostName

data class HandshakeRecordProfile(
    /** 按顺序排列：EncryptedExtensions, Certificate, CertificateVerify, Finished(, NewSessionTicket...) 每条 record 的密文长度 */
    val recordLengths: List<Int>,
)

private const val RECORD_HEADER_LEN = 5
private const val CONTENT_TYPE_HANDSHAKE = 0x16
private const val CONTENT_TYPE_APPLICATION_DATA = 0x17

/**
 * 用 Netty 自带的 SslHandler 作为一个真实 TLS 客户端连接 fallback dest，
 * 在 record 层原始字节上"偷听" ServerHello 之后、我们自己发出 Finished 之前
 * 收到的所有 0x17 (application_data) record 的长度。全程不需要解密内容。
 */
class FallbackHandshakeRecordModel(
    private val fallbackDest: RealityConfig.FallbackDest,
    private val group: EventLoopGroup
) {

    /**
     * Learn handshake record model from fallback-dest
     *
     * @return the handshake record profile
     */
    fun learn(): HandshakeRecordProfile {
        val host = fallbackDest.host
        val port = fallbackDest.port
        try {
            val resultFuture = CompletableFuture<HandshakeRecordProfile>()
            val sslContext = SslContextBuilder.forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE) // 只是探测行为，不需要校验证书链
                .build()

            val bootstrap = Bootstrap()
                .group(group)
                .channel(NioSocketChannel::class.java)
                .handler(object : ChannelInitializer<SocketChannel>() {
                    override fun initChannel(ch: SocketChannel) {
                        val recorder = RecordSniffingHandler()
                        val sslHandler = sslContext.newHandler(ch.alloc(), host, port)

                        if (isDnsName(host)) {
                            val engine = sslHandler.engine()
                            val params = engine.sslParameters
                            params.serverNames = listOf(SNIHostName(host))
                            engine.sslParameters = params
                        }

                        sslHandler.handshakeFuture().addListener { future ->
                            if (future.isSuccess) {
                                resultFuture.complete(HandshakeRecordProfile(recorder.applicationDataRecordLengths.toList()))
                            } else {
                                resultFuture.completeExceptionally(future.cause())
                            }
                            ch.close()
                        }

                        // recorder 必须放在 sslHandler 之前（更靠近 socket），
                        // 这样它拿到的是加/解密之前的原始 record 字节。
                        ch.pipeline()
                            .addLast(recorder)
                            .addLast(sslHandler)
                    }
                })

            bootstrap.connect(host, port).addListener { future ->
                if (!future.isSuccess) resultFuture.completeExceptionally(future.cause())
            }

            return resultFuture.get(10, TimeUnit.SECONDS)
        } finally {
            group.shutdownGracefully()
        }
    }

    private fun isDnsName(host: String): Boolean =
        host.isNotBlank() && host.any { it.isLetter() }

    /** 只读、不消费、不修改数据，原样透传给下一个 handler */
    private class RecordSniffingHandler : ChannelDuplexHandler() {

        val applicationDataRecordLengths = mutableListOf<Int>()

        @Volatile
        private var capturingDone = false

        // 跨多次 channelRead 拼接不完整的 5 字节 record header
        private var headerCarry = ByteArray(0)

        // 当前 record body 还剩多少字节没跳过（跨包时用）
        private var remainingBodyBytes = 0

        override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
            if (msg is ByteBuf && !capturingDone) {
                parseInboundRecords(msg)
            }
            ctx.fireChannelRead(msg)
        }

        override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
            if (!capturingDone && msg is ByteBuf && containsNonHandshakeRecord(msg)) {
                capturingDone = true
            }
            ctx.write(msg, promise)
        }

        private fun containsNonHandshakeRecord(buf: ByteBuf): Boolean {
            var idx = buf.readerIndex()
            val writerIndex = buf.writerIndex()
            while (idx + RECORD_HEADER_LEN <= writerIndex) {
                val type = buf.getUnsignedByte(idx).toInt()
                if (type != CONTENT_TYPE_HANDSHAKE) return true
                val length = buf.getUnsignedShort(idx + 3)
                idx += RECORD_HEADER_LEN + length
            }
            return false
        }

        private fun parseInboundRecords(buf: ByteBuf) {
            var idx = buf.readerIndex()
            val writerIndex = buf.writerIndex()

            if (remainingBodyBytes > 0) {
                val skip = minOf(remainingBodyBytes, writerIndex - idx)
                remainingBodyBytes -= skip
                idx += skip
            }

            while (remainingBodyBytes == 0) {
                val availableForHeader = writerIndex - idx
                val totalHeaderBytes = headerCarry.size + availableForHeader
                if (totalHeaderBytes < RECORD_HEADER_LEN) {
                    val newCarry = ByteArray(totalHeaderBytes)
                    headerCarry.copyInto(newCarry)
                    buf.getBytes(idx, newCarry, headerCarry.size, availableForHeader)
                    headerCarry = newCarry
                    return
                }

                val header = ByteArray(RECORD_HEADER_LEN)
                headerCarry.copyInto(header)
                val bytesNeeded = RECORD_HEADER_LEN - headerCarry.size
                buf.getBytes(idx, header, headerCarry.size, bytesNeeded)
                idx += bytesNeeded
                headerCarry = ByteArray(0)

                val type = header[0].toInt() and 0xFF
                val length = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
                if (type == CONTENT_TYPE_APPLICATION_DATA) {
                    applicationDataRecordLengths.add(length)
                }

                val bodyAvailable = writerIndex - idx
                if (length <= bodyAvailable) {
                    idx += length
                } else {
                    remainingBodyBytes = length - bodyAvailable
                    idx = writerIndex
                }
            }
        }
    }

}