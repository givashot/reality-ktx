package org.givashot.tls

import org.bouncycastle.tls.ServerHello
import java.security.PrivateKey

data class ServerHelloWrapper(
    val base: ServerHello,
    val sharedSecret: ByteArray,
    // 这个必须保存下来，后面 ECDH 还要用
    val serverEphemeralPrivateKey: ByteArray,
    // ServerHello.key_share 里面发给客户端的 32 bytes
    val serverEphemeralPublicKey: ByteArray,
    // 实际选择的 TLS 1.3 cipher suite
    val cipherSuite: CipherSuite
)

data class CipherSuite(
    val id: Int,                    // e.g. 0x1301 = TLS_AES_128_GCM_SHA256
    val hash: String,               // "SHA-256"
    val aead: String,               // "AES/GCM/NoPadding" or "ChaCha20-Poly1305"
    val keyLen: Int,                // 16 or 32
    val ivLen: Int = 12,
    val tagLen: Int = 16
) {
    val hashLength: Int
        get() = when (hash) {
            "SHA-256" -> 32
            "SHA-384" -> 48
            else -> error("Unsupported TLS 1.3 hash: $hash")
        }

    companion object {
        const val TLS_AES_128_GCM_SHA256 = 0x1301
        const val TLS_AES_256_GCM_SHA384 = 0x1302
        const val TLS_CHACHA20_POLY1305_SHA256 = 0x1303

        fun fromId(id: Int): CipherSuite = when (id) {
            TLS_AES_128_GCM_SHA256 -> CipherSuite(id, "SHA-256", "AES/GCM/NoPadding", 16)
            TLS_AES_256_GCM_SHA384 -> CipherSuite(id, "SHA-384", "AES/GCM/NoPadding", 32)
            TLS_CHACHA20_POLY1305_SHA256 -> CipherSuite(id, "SHA-256", "ChaCha20-Poly1305", 32)
            else -> error("Unsupported TLS 1.3 cipher suite: 0x${id.toString(16)}")
        }
    }
}

data class HandshakeSecrets(
    val handshakeSecret: ByteArray,
    val serverHandshakeTrafficSecret: ByteArray,
    val clientHandshakeTrafficSecret: ByteArray,
    val serverWriteKey: ByteArray,
    val serverWriteIv: ByteArray,
    val clientWriteKey: ByteArray,
    val clientWriteIv: ByteArray,
    val transcriptHash: ByteArray,   // ClientHello ... ServerHello 的 hash
    val cipherSuite: CipherSuite,
    val masterSecret: ByteArray
)

data class ServerCertificateCredentials(
    val certificateChain: List<ByteArray>,
    val privateKey: PrivateKey,
    val signatureScheme: Int,
    val jcaSignatureAlgorithm: String,
)