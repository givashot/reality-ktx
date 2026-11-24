package org.givashot.tls.handshake

import org.givashot.tls.constant.TLS_HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS_KEY
import org.givashot.tls.constant.TLS_VERSION_1_3

@Suppress("ArrayInDataClass")
data class ServerHello(
    val legacyVersion: Int,
    val random: ByteArray,
    val sessionId: ByteArray,
    val cipherSuite: Int,
    /** Extensions in wire/insertion order. */
    val extensions: LinkedHashMap<Int, ByteArray>,
    internal val sharedSecret: ByteArray? = null,
) {
    val extensionOrder: List<Int> get() = extensions.keys.toList()

    /**
     * The negotiated protocol version: the supported_versions extension when present (TLS 1.3),
     * otherwise the legacy_version field.
     */
    val selectedVersion: Int
        get() {
            val data = extensions[TLS_HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS_KEY]
            return if (data != null && data.size == 2) {
                ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
            } else {
                legacyVersion
            }
        }

    val isTls13: Boolean get() = selectedVersion == TLS_VERSION_1_3
}
