package org.givashot.tls

import org.givashot.tls.constant.TLS_MAX_RECORD_SIZE
import org.givashot.tls.constant.TLS_RECORD_HEADER_LENGTH

data class ServerProfile(
    /** 服务端支持的 TLS 1.3 cipher suite(id 列表),顺序在 SERVER_PREFERENCE 模式下即服务端偏好顺序 */
    val cipherSuites: List<Int> = DEFAULT_CIPHER_SUITES,
    val cipherSelection: CipherSelectionMode = CipherSelectionMode.CLIENT_PREFERENCE,
    /** 预留:是否在 ServerHello 后发送 ChangeCipherSpec。本期不实现,只允许 false */
    val sendChangeCipherSpec: Boolean = false,
    /** 预留:ServerHello 扩展顺序。本期不实现,只允许 null(表示沿用现有行为) */
    val extensionOrder: List<Int>? = null,
    /** 加密握手 flight(以及见下文说明的应用数据)的目标记录长度画像,由 app-server 从目标站学习 */
    val recordLengths: List<Int>,
    /** 入站记录(含 5 字节记录头)大小上限 */
    val maxRecordSize: Int = TLS_MAX_RECORD_SIZE,
) {
    init {
        require(cipherSuites.isNotEmpty())
        require(cipherSuites.all { it in DEFAULT_CIPHER_SUITES })
        require(recordLengths.isNotEmpty())
        require(maxRecordSize > TLS_RECORD_HEADER_LENGTH)
        require(!sendChangeCipherSpec) { "sendChangeCipherSpec is reserved and not supported yet" }
        require(extensionOrder == null) { "extensionOrder is reserved and not supported yet" }
    }

    enum class CipherSelectionMode { CLIENT_PREFERENCE, SERVER_PREFERENCE }

    companion object {
        val DEFAULT_CIPHER_SUITES = listOf(0x1301, 0x1302, 0x1303)
    }
}
