package org.givashot.tls

import org.bouncycastle.tls.*
import java.nio.charset.Charset
import java.util.*

const val BODY_OFFSET_BASE_HANDSHAKE = 4
const val BODY_OFFSET_BASE_TLS_RECORD = 9

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
}
