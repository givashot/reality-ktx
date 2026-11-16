package org.givashot.reality.fallback

import io.netty.bootstrap.Bootstrap
import io.netty.channel.ChannelInitializer
import io.netty.channel.EventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.SslHandler
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import org.givashot.reality.config.RealityConfig
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.net.ssl.SNIHostName

data class HandshakeRecordProfile(
    /** 按顺序排列：EncryptedExtensions, Certificate, CertificateVerify, Finished(, NewSessionTicket...) 每条 record 的密文长度 */
    val recordLengths: List<Int>,
    /** Fallback 服务端 ServerHello 中扩展的顺序 */
    val serverHelloExtensionOrder: List<Int>,
)

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
                    configureSni(sslHandler, host)

                    sslHandler.handshakeFuture().addListener { future ->
                        if (future.isSuccess) {
                            completeProfile(recorder, resultFuture)
                        } else {
                            resultFuture.completeExceptionally(future.cause())
                        }
                        ch.close()
                    }

                    ch.pipeline()
                        .addLast(recorder)
                        .addLast(sslHandler)
                }
            })

        val connectFuture = bootstrap.connect(host, port)
        connectFuture.addListener { future ->
            if (!future.isSuccess) resultFuture.completeExceptionally(future.cause())
        }

        return try {
            resultFuture.get(10, TimeUnit.SECONDS)
        } catch (timeout: TimeoutException) {
            connectFuture.channel().close()
            throw timeout
        } catch (interrupted: InterruptedException) {
            connectFuture.channel().close()
            Thread.currentThread().interrupt()
            throw interrupted
        }
    }

    private fun completeProfile(recorder: RecordSniffingHandler, resultFuture: CompletableFuture<HandshakeRecordProfile>) {
        val extensionOrder = recorder.serverHelloExtensionOrder
        if (extensionOrder == null) {
            resultFuture.completeExceptionally(IllegalStateException("Fallback ServerHello extensions were not captured"))
        } else {
            resultFuture.complete(HandshakeRecordProfile(recorder.applicationDataRecordLengths, extensionOrder))
        }
    }

    private fun configureSni(sslHandler: SslHandler, host: String) {
        if (!isDnsName(host)) return
        val engine = sslHandler.engine()
        val params = engine.sslParameters
        params.serverNames = listOf(SNIHostName(host))
        engine.sslParameters = params
    }

    private fun isDnsName(host: String): Boolean =
        host.isNotBlank() && host.any { it.isLetter() }
}
