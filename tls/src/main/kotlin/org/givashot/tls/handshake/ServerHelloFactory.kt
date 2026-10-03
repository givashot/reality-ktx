package org.givashot.tls.handshake

import org.bouncycastle.tls.*
import org.givashot.tls.ServerProfile
import org.givashot.tls.constant.TLS_HANDSHAKE_SERVER_HELLO_CONTENT_TYPE
import org.givashot.tls.crypto.*
import java.io.ByteArrayOutputStream
import java.util.*

internal fun newServerHello(
    clientHello: ClientHelloWrapper,
    profile: ServerProfile = ServerProfile(recordLengths = listOf(2048)),
): ServerHelloWrapper {
    val clientSuites = clientHello.base.cipherSuites
    val cipherSuiteType = when (profile.cipherSelection) {
        ServerProfile.CipherSelectionMode.CLIENT_PREFERENCE ->
            clientSuites.firstOrNull { it in profile.cipherSuites }
                ?: error("No mutually supported TLS 1.3 cipher suite")
        ServerProfile.CipherSelectionMode.SERVER_PREFERENCE ->
            profile.cipherSuites.firstOrNull { it in clientSuites }
                ?: error("No mutually supported TLS 1.3 cipher suite")
    }
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
    // 5.copy session id from client hello
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

internal fun ServerHello.encodeHandshake(): ByteArray {
    val body = ByteArrayOutputStream()
    encode(null, body)
    return tlsHandshakeMessage(TLS_HANDSHAKE_SERVER_HELLO_CONTENT_TYPE, body.toByteArray())
}
