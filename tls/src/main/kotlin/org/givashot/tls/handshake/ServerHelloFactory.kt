package org.givashot.tls.handshake

import org.bouncycastle.tls.*
import org.givashot.tls.ServerProfile
import org.givashot.tls.connection.TlsError
import org.givashot.tls.connection.TlsProtocolException
import org.givashot.tls.constant.TLS_HANDSHAKE_SERVER_HELLO_CONTENT_TYPE
import org.givashot.tls.crypto.*
import java.io.ByteArrayOutputStream
import java.util.*

/** Cheap, crypto-free negotiation. Failure means the ClientHello is not for us. */
internal fun negotiate(clientHello: ClientHelloWrapper, profile: ServerProfile): NegotiatedParameters {
    val clientSuites = clientHello.base.cipherSuites
    val cipherSuiteId = when (profile.cipherSelection) {
        ServerProfile.CipherSelectionMode.CLIENT_PREFERENCE ->
            clientSuites.firstOrNull { it in profile.cipherSuites }
        ServerProfile.CipherSelectionMode.SERVER_PREFERENCE ->
            profile.cipherSuites.firstOrNull { it in clientSuites }
    } ?: throw TlsProtocolException(TlsError.Peer.NegotiationFailed("No mutually supported TLS 1.3 cipher suite"))
    if (clientHello.clientPubKey == null) {
        throw TlsProtocolException(TlsError.Peer.NegotiationFailed("Client X25519 key share is missing"))
    }
    return NegotiatedParameters(cipherSuite = CipherSuite.fromId(cipherSuiteId))
}

/** Generates the ephemeral key, shared secret and ServerHello for an already negotiated ClientHello. */
internal fun newServerHello(
    clientHello: ClientHelloWrapper,
    negotiated: NegotiatedParameters,
): ServerHelloWrapper {
    val clientPublicKey = checkNotNull(clientHello.clientPubKey) { "Client public key is missing" }
    val serverPrivate = generateX25519PrivateKey()
    val serverPublicKey = serverPrivate.deriveX25519PublicKey()

    val serverExtensions = Hashtable<Int, Any>()
    TlsExtensionsUtils.addSupportedVersionsExtensionServer(serverExtensions, negotiated.version)
    TlsExtensionsUtils.addKeyShareServerHello(serverExtensions, KeyShareEntry(negotiated.namedGroup, serverPublicKey))

    val serverHello = ServerHello(
        ProtocolVersion.TLSv12,
        ByteArray(32).also(globalSecureRandom::nextBytes),
        clientHello.base.sessionID,
        negotiated.cipherSuite.id,
        serverExtensions,
    )
    return ServerHelloWrapper(
        base = serverHello,
        sharedSecret = calcSharedSecret(serverPrivate, clientPublicKey),
        serverEphemeralPrivateKey = serverPrivate,
        serverEphemeralPublicKey = serverPublicKey,
        cipherSuite = negotiated.cipherSuite,
    )
}

internal fun ServerHello.encodeHandshake(): ByteArray {
    val body = ByteArrayOutputStream()
    encode(null, body)
    return tlsHandshakeMessage(TLS_HANDSHAKE_SERVER_HELLO_CONTENT_TYPE, body.toByteArray())
}
