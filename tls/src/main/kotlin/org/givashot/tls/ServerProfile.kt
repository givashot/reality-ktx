package org.givashot.tls

data class ServerProfile(
    /** 服务端支持的 TLS 1.3 cipher suite(id 列表),顺序在 SERVER_PREFERENCE 模式下即服务端偏好顺序 */
    val cipherSuites: List<Int> = DEFAULT_CIPHER_SUITES,
    val cipherSelection: CipherSelectionMode = CipherSelectionMode.CLIENT_PREFERENCE,
    /** 预留:ServerHello 扩展顺序。本期不实现,只允许 null(表示沿用现有行为) */
    val extensionOrder: List<Int>? = null,
) {
    init {
        require(cipherSuites.isNotEmpty())
        require(cipherSuites.all { it in DEFAULT_CIPHER_SUITES })
        require(extensionOrder == null) { "extensionOrder is reserved and not supported yet" }
    }

    enum class CipherSelectionMode { CLIENT_PREFERENCE, SERVER_PREFERENCE }

    companion object {
        val DEFAULT_CIPHER_SUITES = listOf(0x1301, 0x1302, 0x1303)
    }
}
