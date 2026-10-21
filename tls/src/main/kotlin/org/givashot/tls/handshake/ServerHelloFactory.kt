package org.givashot.tls.handshake

import org.bouncycastle.tls.KeyShareEntry
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.ServerHello
import org.bouncycastle.tls.TlsExtensionsUtils
import org.givashot.tls.ServerProfile
import org.givashot.tls.connection.NegotiationFailedException
import org.givashot.tls.crypto.*
import java.util.*

/** Cheap, crypto-free negotiation. Failure means the ClientHello is not for us. */
internal fun negotiate(clientHello: ClientHelloWrapper, profile: ServerProfile): NegotiatedParameters {
    if (!clientHello.supportsTls13) {
        throw NegotiationFailedException("Client does not support TLS 1.3")
    }
    val clientSuites = clientHello.base.cipherSuites
    val cipherSuiteId = when (profile.cipherSelection) {
        ServerProfile.CipherSelectionMode.CLIENT_PREFERENCE ->
            clientSuites.firstOrNull { it in profile.cipherSuites }
        ServerProfile.CipherSelectionMode.SERVER_PREFERENCE ->
            profile.cipherSuites.firstOrNull { it in clientSuites }
    } ?: throw NegotiationFailedException("No mutually supported TLS 1.3 cipher suite")
    if (clientHello.clientPubKey == null) {
        throw NegotiationFailedException("Client X25519 key share is missing")
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