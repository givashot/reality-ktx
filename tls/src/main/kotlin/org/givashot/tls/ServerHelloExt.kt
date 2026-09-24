package org.givashot.tls

import org.bouncycastle.tls.*
import java.io.ByteArrayOutputStream
import java.util.*
import org.bouncycastle.tls.CipherSuite as BCTLSCipherSuite

fun buildServerHello(
    clientHello: ClientHelloWrapper,
): ServerHelloWrapper {
    // 1. 从 ClientHello 选择 TLS 1.3 cipher suite
    val clientSuites = clientHello.base.cipherSuites
    val preferred = intArrayOf(
        BCTLSCipherSuite.TLS_AES_128_GCM_SHA256,
        BCTLSCipherSuite.TLS_AES_256_GCM_SHA384,
        BCTLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256
    )
    val cipherSuiteType =
        preferred.firstOrNull { it in clientSuites } ?: error("No mutually supported TLS 1.3 cipher suite")
    val cipherSuite = CipherSuite.fromId(cipherSuiteType)
    // 2. 找 ClientHello 的 X25519 key_share
    val clientPublicKey = clientHello.clientPubKey ?: throw Exception("Client public key is missing")
    // 3. REALITY / TLS 1.3：生成临时 X25519 keypair
    val serverPrivate = generateX25519PrivateKey()
    val serverPublicKey = serverPrivate.deriveX25519PublicKey()
    // 4. 构造 ServerHello extensions
    val serverExtensions = Hashtable<Int, Any>()
    // TLS 1.3:
    // supported_versions = TLS 1.3
    TlsExtensionsUtils.addSupportedVersionsExtensionServer(
        serverExtensions,
        ProtocolVersion.TLSv13
    )
    // TLS 1.3:
    // key_share = X25519(server ephemeral public key)
    TlsExtensionsUtils.addKeyShareServerHello(
        serverExtensions,
        KeyShareEntry(
            NamedGroup.x25519,
            serverPublicKey
        )
    )
    // 5. REALITY：ServerHello.session_id = ClientHello.session_id
    val sessionId = clientHello.base.sessionID
    // ------------------------------------------------------------
    // 6. 构造标准 TLS ServerHello
    // ------------------------------------------------------------
    val serverHello = ServerHello(
        ProtocolVersion.TLSv12,
        ByteArray(32).also(globalSecureRandom::nextBytes),
        sessionId,
        cipherSuiteType,
        serverExtensions
    )
    return ServerHelloWrapper(
        base = serverHello,
        sharedSecret = calcSharedSecret(serverPrivate, clientPublicKey),
        serverEphemeralPrivateKey = serverPrivate,
        serverEphemeralPublicKey = serverPublicKey,
        cipherSuite = cipherSuite
    )
}

fun encodeTLSRecord(handshakeMessage: ByteArray): ByteArray {
    return tlsRecord(22, handshakeMessage)
}

fun ServerHello.encodeHandshake(): ByteArray {
    val body = ByteArrayOutputStream()
    encode(null, body)
    return tlsHandshakeMessage(2, body.toByteArray())
}
