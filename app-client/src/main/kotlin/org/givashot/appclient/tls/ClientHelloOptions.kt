package org.givashot.appclient.tls

import org.bouncycastle.tls.*
import org.givashot.tls.deriveX25519PublicKey
import org.givashot.tls.generateX25519PrivateKey
import org.givashot.tls.globalSecureRandom
import java.io.ByteArrayOutputStream
import java.util.*

private const val TLS_HANDSHAKE_CONTENT_TYPE = 22
private const val CLIENT_HELLO_HANDSHAKE_TYPE = 1

data class ClientHelloOptions(
    val sni: String? = null,
    val sessionId: ByteArray = ByteArray(32),
    val random: ByteArray = ByteArray(32).also(globalSecureRandom::nextBytes),
    val legacyVersion: ProtocolVersion = ProtocolVersion.TLSv12,
    val cipherSuites: IntArray = intArrayOf(
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256
    ),
    val extensions: Map<Int, ByteArray> = emptyMap(),
)

object ClientHelloBuilder {

    fun build(options: ClientHelloOptions): ClientHello {
        require(options.sessionId.size <= 32) { "Session-id must contain at most 32 bytes" }
        require(options.cipherSuites.isNotEmpty()) { "At least one cipher suite is required" }

        val random = options.random
        require(random.size == 32) { "Random must contain exactly 32 bytes" }

        val extensions = Hashtable<Int, ByteArray>()
        extensions.putAll(options.extensions.mapValues { it.value.copyOf() })

        // 1. SNI 扩展
        options.sni?.let { sni ->
            require(sni.isNotBlank()) { "SNI must not be blank" }
            val names = Vector<ServerName>().apply {
                add(ServerName(0, sni.toByteArray(Charsets.US_ASCII)))
            }
            extensions[TlsExtensionsUtils.EXT_server_name] =
                TlsExtensionsUtils.createServerNameExtensionClient(names)
        }

        // 2. Supported Versions 扩展 (TLS 1.3 必需)
        if (!extensions.containsKey(TlsExtensionsUtils.EXT_supported_versions)) {
            extensions[TlsExtensionsUtils.EXT_supported_versions] =
                TlsExtensionsUtils.createSupportedVersionsExtensionClient(
                    arrayOf(ProtocolVersion.TLSv13, ProtocolVersion.TLSv12),
                )
        }

        // 3. Supported Groups 扩展 (X25519, secp256r1)
        if (!extensions.containsKey(TlsExtensionsUtils.EXT_supported_groups)) {
            extensions[TlsExtensionsUtils.EXT_supported_groups] =
                TlsExtensionsUtils.createSupportedGroupsExtension(
                    intArrayOf(NamedGroup.x25519, NamedGroup.secp256r1),
                )
        }

        // 4. Key Share 扩展
        if (!extensions.containsKey(TlsExtensionsUtils.EXT_key_share)) {
            extensions[TlsExtensionsUtils.EXT_key_share] = generateKeyShareExtension()
        }

        return ClientHello(
            options.legacyVersion,
            random.copyOf(),
            options.sessionId.copyOf(),
            null, // cookie
            options.cipherSuites.copyOf(),
            extensions,
            0, // binders length
        )
    }

    internal fun createX25519KeyShareExtension(publicKey: ByteArray): ByteArray {
        require(publicKey.size == 32) {
            "X25519 public key must contain exactly 32 bytes"
        }

        val keyShareEntry = KeyShareEntry(NamedGroup.x25519, publicKey.copyOf())
        return TlsExtensionsUtils.createKeyShareClientHello(
            Vector<KeyShareEntry>().apply { add(keyShareEntry) },
        )
    }

    private fun generateKeyShareExtension(): ByteArray {
        return createX25519KeyShareExtension(
            generateX25519PrivateKey().deriveX25519PublicKey()
        )
    }
}

fun ClientHello.encodeTLSRecord(): ByteArray {
    val body = ByteArrayOutputStream()
    this.encode(null, body)

    val handshake = ByteArrayOutputStream(body.size() + 4)
    handshake.write(CLIENT_HELLO_HANDSHAKE_TYPE)
    TlsUtils.writeUint24(body.size(), handshake)
    handshake.write(body.toByteArray())

    val record = ByteArrayOutputStream(handshake.size() + 5)
    record.write(TLS_HANDSHAKE_CONTENT_TYPE)

    // RFC 8446 规定外层 TLS Record Header 必须为 TLS 1.2 (0x0303) 或 TLS 1.0 (0x0301)
    TlsUtils.writeVersion(ProtocolVersion.TLSv12, record)

    TlsUtils.writeUint16(handshake.size(), record)
    record.write(handshake.toByteArray())

    return record.toByteArray()
}