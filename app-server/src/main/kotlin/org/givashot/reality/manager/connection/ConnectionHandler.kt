package org.givashot.reality.manager.connection

import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.util.ReferenceCountUtil
import org.givashot.reality.authentication.AuthResult
import org.givashot.reality.tls.RealityTLSHandshakeService
import org.givashot.reality.tls.TlsHandshakePhase
import org.givashot.tls.ClientHelloWrapper
import org.givashot.tls.decryptApplicationData
import org.givashot.tls.deriveApplicationSecrets
import org.givashot.tls.verifyAndDecryptClientFinished

/**
 * 鉴权通过后接管连接：在加入 pipeline 的同时驱动 [ConnectionManager]。
 *
 * [handlerAdded] 在 `addAfter` 时同步触发，早于路由 Handler 移除时下传的粘包残留字节，
 * 因此 TLS 握手和隧道会先于任何后续数据完成挂载。
 */
class ConnectionHandler(
    private val connectionManager: ConnectionManager,
    private val clientHelloWrapper: ClientHelloWrapper,
    private val result: AuthResult.Success,
) : ChannelInboundHandlerAdapter() {

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        connectionManager.onAuthenticated(ctx.channel(), clientHelloWrapper, result)
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        val state = ctx.channel().attr(RealityTLSHandshakeService.TLS_STATE_KEY).get()
        if (state == null) {
            ReferenceCountUtil.release(msg)
            ctx.close()
            return
        }
        if (msg is ByteBuf) {
            val record = ByteArray(msg.readableBytes())
            msg.readBytes(record)
            msg.release()
            when (state.phase) {
                TlsHandshakePhase.SERVER_FLIGHT_SENT -> {
                    val expectedTranscriptHash = state.serverFlightTranscriptHash ?: run {
                        ctx.close()
                        return
                    }
                    val clientFinished = verifyAndDecryptClientFinished(
                        record,
                        state.handshakeSecrets,
                        expectedTranscriptHash,
                        state.clientHandshakeSequenceNumber,
                    ) ?: run {
                        ctx.close()
                        return
                    }
                    state.clientHandshakeSequenceNumber++
                    state.applicationSecrets = deriveApplicationSecrets(
                        state.handshakeSecrets,
                        expectedTranscriptHash,
                    )
                    state.transcript += clientFinished
                    state.phase = TlsHandshakePhase.APPLICATION_DATA
                    state.clientApplicationSequenceNumber = 0
                }

                TlsHandshakePhase.APPLICATION_DATA -> {
                    val applicationSecrets = state.applicationSecrets ?: run {
                        ctx.close()
                        return
                    }
                    val plaintext = runCatching {
                        decryptApplicationData(
                            record,
                            applicationSecrets,
                            state.clientApplicationSequenceNumber,
                        )
                    }.getOrElse {
                        ctx.close()
                        return
                    }
                    state.clientApplicationSequenceNumber++
                    ctx.fireChannelRead(Unpooled.wrappedBuffer(plaintext))
                }
                else -> ctx.close()
            }
        } else {
            ReferenceCountUtil.release(msg)
            ctx.close()
        }
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        ctx.channel().attr(RealityTLSHandshakeService.TLS_STATE_KEY).get()?.phase = TlsHandshakePhase.CLOSED
        ctx.fireChannelInactive()
    }

}
