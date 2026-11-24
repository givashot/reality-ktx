package org.givashot.tls.handshake

import org.givashot.tls.connection.DecodeErrorException
import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE_CLIENT_HELLO
import org.givashot.tls.constant.TLS_HANDSHAKE_HEADER_LENGTH
import org.givashot.tls.constant.TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH

object ClientHelloParser {
    fun parse(message: HandshakeMessage): ClientHello {
        if (message.type != TLS_HANDSHAKE_CONTENT_TYPE_CLIENT_HELLO) {
            throw DecodeErrorException("Handshake message is not a ClientHello: type=${message.type}")
        }
        if (message.encodedBytes.size > TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH) {
            throw DecodeErrorException(
                "ClientHello size ${message.encodedBytes.size} exceeds limit $TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH"
            )
        }
        val body = message.body
        // legacy_version (2) + random (32) + session_id_len (1)
        if (body.size < 35) throw DecodeErrorException("ClientHello is truncated")

        var offset = 0
        val legacyVersion = readUint16(body, offset)
        offset += 2

        val random = body.copyOfRange(offset, offset + 32)
        offset += 32

        val sessionIdLen = body[offset++].toInt() and 0xFF
        if (sessionIdLen > 32) throw DecodeErrorException("ClientHello session ID is too large")
        val sessionIdOffset = offset
        if (offset + sessionIdLen > body.size) throw DecodeErrorException("ClientHello session ID is truncated")
        val sessionId = body.copyOfRange(offset, offset + sessionIdLen)
        offset += sessionIdLen

        if (offset + 2 > body.size) throw DecodeErrorException("ClientHello cipher_suites length is truncated")
        val cipherSuitesByteLen = readUint16(body, offset)
        offset += 2
        if (cipherSuitesByteLen < 2 || cipherSuitesByteLen % 2 != 0) {
            throw DecodeErrorException("ClientHello cipher_suites length is invalid: $cipherSuitesByteLen")
        }
        if (offset + cipherSuitesByteLen > body.size) throw DecodeErrorException("ClientHello cipher_suites is truncated")
        val cipherSuites = IntArray(cipherSuitesByteLen / 2) { i ->
            readUint16(body, offset + i * 2)
        }
        offset += cipherSuitesByteLen

        if (offset + 1 > body.size) throw DecodeErrorException("ClientHello compression_methods length is truncated")
        val compressionLen = body[offset++].toInt() and 0xFF
        if (compressionLen < 1) {
            throw DecodeErrorException("ClientHello compression_methods length is invalid: $compressionLen")
        }
        if (offset + compressionLen > body.size) {
            throw DecodeErrorException("ClientHello compression_methods is truncated")
        }
        val compressionMethods = body.copyOfRange(offset, offset + compressionLen)
        offset += compressionLen

        val extensions = LinkedHashMap<Int, ByteArray>()
        if (offset < body.size) {
            if (offset + 2 > body.size) throw DecodeErrorException("ClientHello extensions length is truncated")
            val extensionsLen = readUint16(body, offset)
            offset += 2
            if (offset + extensionsLen != body.size) {
                throw DecodeErrorException("ClientHello extensions length mismatch")
            }
            while (offset < body.size) {
                if (offset + 4 > body.size) throw DecodeErrorException("ClientHello extension header is truncated")
                val extType = readUint16(body, offset)
                val extLen = readUint16(body, offset + 2)
                offset += 4
                if (offset + extLen > body.size) throw DecodeErrorException("ClientHello extension is truncated")
                if (extensions.containsKey(extType)) {
                    throw DecodeErrorException("Duplicate ClientHello extension: $extType")
                }
                extensions[extType] = body.copyOfRange(offset, offset + extLen)
                offset += extLen
            }
        }

        return ClientHello(
            legacyVersion = legacyVersion,
            random = random,
            sessionId = sessionId,
            cipherSuites = cipherSuites,
            compressionMethods = compressionMethods,
            extensions = extensions,
            handshakeAndBody = message.encodedBytes,
            sessionIdOffsetBaseHandshake = TLS_HANDSHAKE_HEADER_LENGTH + sessionIdOffset,
        )
    }

    private fun readUint16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
}

fun HandshakeMessage.parseClientHello(): ClientHello = ClientHelloParser.parse(this)
