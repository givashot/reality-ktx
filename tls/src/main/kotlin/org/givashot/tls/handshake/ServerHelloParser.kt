package org.givashot.tls.handshake

import org.givashot.tls.connection.DecodeErrorException
import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE_SERVER_HELLO
import org.givashot.tls.constant.TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET_BASE_BODY

object ServerHelloParser {
    /** Parses a complete ServerHello handshake message. Throws [DecodeErrorException] when malformed. */
    fun parse(message: HandshakeMessage): ServerHello {
        if (message.type != TLS_HANDSHAKE_CONTENT_TYPE_SERVER_HELLO) {
            throw DecodeErrorException("Handshake message is not a ServerHello: type=${message.type}")
        }
        val body = message.body
        val sessionIdLengthOffset = TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET_BASE_BODY
        if (sessionIdLengthOffset + 1 > body.size) throw DecodeErrorException("ServerHello is truncated")
        val sessionIdLength = body[sessionIdLengthOffset].toInt() and 0xFF
        if (sessionIdLength > 32) throw DecodeErrorException("ServerHello session ID is too large")

        val cipherSuiteOffset = sessionIdLengthOffset + 1 + sessionIdLength
        val compressionOffset = cipherSuiteOffset + 2
        if (compressionOffset + 1 > body.size) throw DecodeErrorException("ServerHello is truncated")

        val legacyVersion = readUint16(body, 0)
        val random = body.copyOfRange(2, 34)
        val sessionId = body.copyOfRange(sessionIdLengthOffset + 1, cipherSuiteOffset)
        val cipherSuite = readUint16(body, cipherSuiteOffset)
        val extensionsLengthOffset = compressionOffset + 1
        if (extensionsLengthOffset == body.size) {
            return ServerHello(legacyVersion, random, sessionId, cipherSuite, LinkedHashMap())
        }
        if (extensionsLengthOffset + 2 > body.size) {
            throw DecodeErrorException("ServerHello extensions length is truncated")
        }

        val extensionsStart = extensionsLengthOffset + 2
        if (extensionsStart + readUint16(body, extensionsLengthOffset) != body.size) {
            throw DecodeErrorException("ServerHello extensions length mismatch")
        }
        return ServerHello(legacyVersion, random, sessionId, cipherSuite, parseExtensions(body, extensionsStart))
    }

    private fun parseExtensions(body: ByteArray, start: Int): LinkedHashMap<Int, ByteArray> {
        val extensions = LinkedHashMap<Int, ByteArray>()
        var offset = start
        while (offset < body.size) {
            if (offset + 4 > body.size) throw DecodeErrorException("ServerHello extension header is truncated")
            val extensionType = readUint16(body, offset)
            val extensionLength = readUint16(body, offset + 2)
            offset += 4
            if (offset + extensionLength > body.size) throw DecodeErrorException("ServerHello extension is truncated")
            if (extensions.containsKey(extensionType)) {
                throw DecodeErrorException("Duplicate ServerHello extension: $extensionType")
            }
            extensions[extensionType] = body.copyOfRange(offset, offset + extensionLength)
            offset += extensionLength
        }
        return extensions
    }

    private fun readUint16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
}

fun HandshakeMessage.parseServerHello(): ServerHello = ServerHelloParser.parse(this)
