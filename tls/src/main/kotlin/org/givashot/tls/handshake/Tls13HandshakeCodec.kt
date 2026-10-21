package org.givashot.tls.handshake

import org.bouncycastle.tls.ClientHello
import org.bouncycastle.tls.ServerHello
import org.givashot.tls.connection.DecodeErrorException
import org.givashot.tls.connection.IllegalParameterException
import org.givashot.tls.constant.*
import org.givashot.tls.ext.writeUint16
import org.givashot.tls.ext.writeUint24
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.Signature

/**
 * TLS 1.3 handshake wire format: message framing, cross-record reassembly, and encoding/decoding of message bodies.
 * Holds nothing but reassembly buffers. Knows nothing about states, secrets, transcripts or keys.
 */
internal class Tls13HandshakeCodec {
    private val clientHelloDecoder = HandshakeMessageDecoder(TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH)
    private val decoder = HandshakeMessageDecoder()

    val clientHelloPendingBytes: Int get() = clientHelloDecoder.bufferedByteCount
    val pendingBytes: Int get() = decoder.bufferedByteCount

    fun feedClientHello(fragment: ByteArray): List<HandshakeMessage> = reassemble(clientHelloDecoder, fragment)

    fun feed(fragment: ByteArray): List<HandshakeMessage> = reassemble(decoder, fragment)

    fun reset() {
        clientHelloDecoder.reset()
        decoder.reset()
    }

    /** Parses a complete ClientHello handshake message (4-byte header included). */
    fun parseClientHello(message: HandshakeMessage): ClientHelloWrapper {
        if (message.encodedBytes.size > TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH) {
            throw DecodeErrorException(
                "ClientHello size ${message.encodedBytes.size} exceeds limit $TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH"
            )
        }
        val encoded = message.encodedBytes
        if (encoded.size < TLS_HANDSHAKE_HEADER_LENGTH + 35) {
            throw DecodeErrorException("ClientHello is truncated")
        }
        val sessionIdLengthOffset = TLS_HANDSHAKE_HEADER_LENGTH + 2 + 32
        val sessionIdLength = encoded[sessionIdLengthOffset].toInt() and 0xFF
        val sessionIdOffset = sessionIdLengthOffset + 1
        if (sessionIdOffset + sessionIdLength > encoded.size) {
            throw DecodeErrorException("ClientHello session ID is truncated")
        }
        val parsed = try {
            ClientHello.parse(
                ByteArrayInputStream(encoded, TLS_HANDSHAKE_HEADER_LENGTH, encoded.size - TLS_HANDSHAKE_HEADER_LENGTH),
                null,
            )
        } catch (e: Exception) {
            throw DecodeErrorException(e.message ?: e.javaClass.simpleName)
        }
        if (sessionIdLength != parsed.sessionID.size) {
            throw DecodeErrorException("ClientHello session ID length mismatch")

        }
        return ClientHelloWrapper(parsed, encoded, sessionIdOffset)
    }

    /** Returns the verify_data, which must be exactly [verifyDataLength] bytes (the hash length of the suite). */
    fun parseFinished(message: HandshakeMessage, verifyDataLength: Int): ByteArray {
        if (message.body.size != verifyDataLength) {
            throw DecodeErrorException(
                "Malformed Finished: verify_data must be $verifyDataLength bytes, got ${message.body.size}"
            )
        }
        return message.body
    }

    fun parseKeyUpdate(message: HandshakeMessage): KeyUpdate {
        if (message.body.size != 1) {
            throw DecodeErrorException("Malformed KeyUpdate: body must contain exactly one byte")
        }
        val requestUpdate = message.body[0].toInt() and 0xFF
        if (requestUpdate != TLS_HANDSHAKE_KEY_UPDATE_NOT_REQUESTED && requestUpdate != TLS_HANDSHAKE_KEY_UPDATE_REQUESTED) {
            throw IllegalParameterException("KeyUpdate has an invalid request value: $requestUpdate")
        }
        return KeyUpdate(requestUpdate)
    }

    fun encodeServerHello(serverHello: ServerHello): ByteArray{
        val body = ByteArrayOutputStream()
        serverHello.encode(null, body)
        return tlsHandshakeMessage(TLS_HANDSHAKE_SERVER_HELLO_CONTENT_TYPE, body.toByteArray())
    }

    fun encodeEncryptedExtensions(data: EncryptedExtensionsData): ByteArray {
        val extensions = data.extensions
        val extensionBytes = ByteArrayOutputStream()
        extensions.forEach { (type, data) ->
            require(type in 0..0xFFFF && data.size <= 0xFFFF)
            extensionBytes.writeUint16(type)
            extensionBytes.writeUint16(data.size)
            extensionBytes.write(data)
        }
        require(extensionBytes.size() <= 0xFFFF) { "EncryptedExtensions is too large" }
        val body = ByteArrayOutputStream()
        body.writeUint16(extensionBytes.size())
        body.write(extensionBytes.toByteArray())
        return tlsHandshakeMessage(TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS_CONTENT_TYPE, body.toByteArray())
    }

    fun encodeCertificate(certificateData: CertificateData): ByteArray {
        require(certificateData.certificateChain.isNotEmpty())
        val certificateList = ByteArrayOutputStream()
        certificateData.certificateChain.forEach { certificate ->
            require(certificate.size <= 0xFFFFFF)
            certificateList.writeUint24(certificate.size)
            certificateList.write(certificate)
            certificateList.writeUint16(0)
        }
        require(certificateList.size() <= 0xFFFFFF) { "Certificate list is too large" }
        val body = ByteArrayOutputStream()
        body.write(0)
        body.writeUint24(certificateList.size())
        body.write(certificateList.toByteArray())
        return tlsHandshakeMessage(TLS_HANDSHAKE_CERTIFICATE_CONTENT_TYPE, body.toByteArray())
    }

    fun encodeCertificateVerify(certificate: CertificateData, transcriptHash: ByteArray): ByteArray {
        val signatureInput = ByteArray(64) { 0x20 } +
                "TLS 1.3, server CertificateVerify".toByteArray(Charsets.US_ASCII) +
                byteArrayOf(0) + transcriptHash
        val signer = Signature.getInstance(certificate.jcaSignatureAlgorithm)
        signer.initSign(certificate.privateKey)
        signer.update(signatureInput)
        val signature = signer.sign()
        val body = ByteArrayOutputStream()
        body.writeUint16(certificate.signatureScheme)
        require(signature.size <= 0xFFFF)
        body.writeUint16(signature.size)
        body.write(signature)
        return tlsHandshakeMessage(TLS_HANDSHAKE_CERTIFICATE_VERIFY_CONTENT_TYPE, body.toByteArray())
    }

    fun encodeFinished(verifyData: ByteArray): ByteArray {
        return tlsHandshakeMessage(type = TLS_HANDSHAKE_FINISH_CONTENT_TYPE, body = verifyData)
    }

    fun encodeKeyUpdate(requestPeer: Boolean): ByteArray =
        tlsHandshakeMessage(
            TLS_HANDSHAKE_KEY_UPDATE_CONTENT_TYPE,
            byteArrayOf(if (requestPeer) 1 else 0),
        )

    private fun reassemble(decoder: HandshakeMessageDecoder, fragment: ByteArray): List<HandshakeMessage> =
        try {
            decoder.feed(fragment)
        } catch (_: IllegalArgumentException) {
            throw DecodeErrorException("Handshake message exceeds the maximum size")
        }

    private fun tlsHandshakeMessage(type: Int, body: ByteArray): ByteArray {
        require(type in 0..255 && body.size <= 0xFFFFFF)
        return byteArrayOf(
            type.toByte(),
            (body.size ushr 16).toByte(),
            (body.size ushr 8).toByte(),
            body.size.toByte(),
        ) + body
    }

}
