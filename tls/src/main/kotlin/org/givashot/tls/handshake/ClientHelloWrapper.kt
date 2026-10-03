package org.givashot.tls.handshake

import org.bouncycastle.tls.*
import org.givashot.tls.connection.TlsError
import org.givashot.tls.connection.TlsProtocolException
import org.givashot.tls.constant.TLS_HANDSHAKE_HEADER_LENGTH
import java.io.ByteArrayInputStream
import java.nio.charset.Charset
import java.util.*

data class ClientHelloWrapper(
    val base: ClientHello,
    val handshakeAndBody: ByteArray,
    val sessionIdOffset: Int,
) {

    /**
     * 从 bctls 的 ClientHello 对象中提取 SNI 主机名
     */
    val sni: String? by lazy {
        val extensions = this.base.extensions
        // 使用 bctls 的工具类解析 ServerName 扩展列表
        val serverNameList = TlsExtensionsUtils.getServerNameExtensionClient(extensions) as? Iterable<ServerName>
        // 遍历 ServerName 列表，查找 HostName 类型 (NameType.host_name)
        serverNameList?.firstOrNull {
            it.nameType == NameType.host_name
        }?.nameData?.toString(Charset.forName("UTF-8"))
    }

    /**
     * Extract x25519 key share(client pub key)
     */
    val clientPubKey: ByteArray? by lazy {
        val extensions = this.base.extensions
        try {
            val keyShares: Vector<*> = TlsExtensionsUtils.getKeyShareClientHello(extensions)
            if (keyShares.isNotEmpty()) {
                for (i in keyShares.indices) {
                    val entry = keyShares.elementAt(i) as? KeyShareEntry ?: continue
                    // 只关心 x25519 (NamedGroup.x25519 = 0x001d)
                    if (entry.namedGroup == NamedGroup.x25519) {
                        val keyExchange = entry.keyExchange
                        // X25519 公钥必须是正好 32 字节
                        if (keyExchange != null && keyExchange.size == 32) {
                            return@lazy keyExchange
                        }
                    }
                }
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    fun aadWithZeroedSessionId(): ByteArray = handshakeAndBody.copyOf().also {
        it.fill(0, sessionIdOffset, sessionIdOffset + base.sessionID.size)
    }

    internal companion object {
        /** Parses a complete ClientHello handshake message (4-byte header included). */
        fun parse(encoded: ByteArray): ClientHelloWrapper {
            if (encoded.size < TLS_HANDSHAKE_HEADER_LENGTH + 35) {
                throw TlsProtocolException(TlsError.Peer.MalformedClientHello("ClientHello is truncated"))
            }
            val sessionIdLengthOffset = TLS_HANDSHAKE_HEADER_LENGTH + 2 + 32
            val sessionIdLength = encoded[sessionIdLengthOffset].toInt() and 0xFF
            val sessionIdOffset = sessionIdLengthOffset + 1
            if (sessionIdOffset + sessionIdLength > encoded.size) {
                throw TlsProtocolException(TlsError.Peer.MalformedClientHello("ClientHello session ID is truncated"))
            }
            val parsed = try {
                ClientHello.parse(
                    ByteArrayInputStream(encoded, TLS_HANDSHAKE_HEADER_LENGTH, encoded.size - TLS_HANDSHAKE_HEADER_LENGTH),
                    null,
                )
            } catch (e: Exception) {
                throw TlsProtocolException(TlsError.Peer.MalformedClientHello(e.message ?: e.javaClass.simpleName))
            }
            if (sessionIdLength != parsed.sessionID.size) {
                throw TlsProtocolException(TlsError.Peer.MalformedClientHello("ClientHello session ID length mismatch"))
            }
            return ClientHelloWrapper(parsed, encoded, sessionIdOffset)
        }
    }
}
