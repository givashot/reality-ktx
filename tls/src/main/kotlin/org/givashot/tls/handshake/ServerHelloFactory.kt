package org.givashot.tls.handshake

import org.givashot.tls.ServerProfile
import org.givashot.tls.connection.NegotiationFailedException
import org.givashot.tls.constant.TLS_HANDSHAKE_EXTENSION_KEY_SHARE_KEY
import org.givashot.tls.constant.TLS_HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS_KEY
import org.givashot.tls.constant.TLS_VERSION_1_2
import org.givashot.tls.crypto.*
import org.givashot.tls.ext.writeUint16
import java.io.ByteArrayOutputStream

/** Cheap, crypto-free negotiation. Failure means the ClientHello is not for us. */
internal fun negotiate(clientHello: ClientHello, profile: ServerProfile): NegotiatedParameters {
    if (!clientHello.supportsTls13) {
        throw NegotiationFailedException("Client does not support TLS 1.3")
    }
    val clientSuites = clientHello.cipherSuites
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
    clientHello: ClientHello,
    negotiated: NegotiatedParameters,
): ServerHello {
    val clientPublicKey = checkNotNull(clientHello.clientPubKey) { "Client public key is missing" }
    val serverPrivate = generateX25519PrivateKey()
    val serverPublicKey = serverPrivate.deriveX25519PublicKey()

    val keyShareExt = ByteArrayOutputStream().apply {
        writeUint16(negotiated.namedGroup)
        writeUint16(serverPublicKey.size)
        write(serverPublicKey)
    }.toByteArray()

    val supportedVersionsExt = ByteArrayOutputStream().apply {
        writeUint16(negotiated.version)
    }.toByteArray()

    val serverExtensions = LinkedHashMap<Int, ByteArray>().apply {
        put(TLS_HANDSHAKE_EXTENSION_KEY_SHARE_KEY, keyShareExt)
        put(TLS_HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS_KEY, supportedVersionsExt)
    }

    return ServerHello(
        legacyVersion = TLS_VERSION_1_2,
        random = ByteArray(32).also(globalSecureRandom::nextBytes),
        sessionId = clientHello.sessionId,
        cipherSuite = negotiated.cipherSuite.id,
        extensions = serverExtensions,
        sharedSecret = calcSharedSecret(serverPrivate, clientPublicKey),
    )
}