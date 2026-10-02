package org.givashot.tls.entity.handshake

import org.bouncycastle.tls.ServerHello

internal data class ServerHelloWrapper(
    val base: ServerHello,
    val sharedSecret: ByteArray,
    // 这个必须保存下来，后面 ECDH 还要用
    val serverEphemeralPrivateKey: ByteArray,
    // ServerHello.key_share 里面发给客户端的 32 bytes
    val serverEphemeralPublicKey: ByteArray,
    // 实际选择的 TLS 1.3 cipher suite
    val cipherSuite: CipherSuite
)
