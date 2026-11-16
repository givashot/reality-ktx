package org.givashot.tls.handshake

import org.givashot.tls.connection.DecodeErrorException
import org.givashot.tls.constant.*

class ServerHelloInfo(
    val legacyVersion: Int,
    val cipherSuite: Int,
    /** Extensions in wire order. */
    val extensions: List<Pair<Int, ByteArray>>,
) {
    val extensionOrder: List<Int> get() = extensions.map { it.first }

    /**
     * The negotiated protocol version: the supported_versions extension when present (TLS 1.3),
     * otherwise the legacy_version field.
     */
    val selectedVersion: Int
        get() {
            val data = extensions.firstOrNull { it.first == TLS_HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS_KEY }?.second
            return if (data != null && data.size == 2) readUint16(data, 0) else legacyVersion
        }

    val isTls13: Boolean get() = selectedVersion == TLS_VERSION_1_3
}

/** Parses a complete ServerHello handshake message. Throws [DecodeErrorException] when malformed. */
fun HandshakeMessage.parseServerHello(): ServerHelloInfo {
    if (type != TLS_HANDSHAKE_CONTENT_TYPE_SERVER_HELLO) {
        throw DecodeErrorException("Handshake message is not a ServerHello: type=$type")
    }
    val sessionIdLengthOffset = TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET_BASE_BODY
    if (sessionIdLengthOffset + 1 > body.size) throw DecodeErrorException("ServerHello is truncated")
    val sessionIdLength = body[sessionIdLengthOffset].toInt() and 0xFF
    if (sessionIdLength > 32) throw DecodeErrorException("ServerHello session ID is too large")

    val cipherSuiteOffset = sessionIdLengthOffset + 1 + sessionIdLength
    val compressionOffset = cipherSuiteOffset + 2
    if (compressionOffset + 1 > body.size) throw DecodeErrorException("ServerHello is truncated")

    val legacyVersion = readUint16(body, 0)
    val cipherSuite = readUint16(body, cipherSuiteOffset)
    val extensionsLengthOffset = compressionOffset + 1
    if (extensionsLengthOffset == body.size) return ServerHelloInfo(legacyVersion, cipherSuite, emptyList())
    if (extensionsLengthOffset + 2 > body.size) throw DecodeErrorException("ServerHello extensions length is truncated")

    val extensionsStart = extensionsLengthOffset + 2
    if (extensionsStart + readUint16(body, extensionsLengthOffset) != body.size) {
        throw DecodeErrorException("ServerHello extensions length mismatch")
    }
    return ServerHelloInfo(legacyVersion, cipherSuite, parseExtensions(body, extensionsStart))
}

private fun parseExtensions(body: ByteArray, start: Int): List<Pair<Int, ByteArray>> {
    val extensions = ArrayList<Pair<Int, ByteArray>>()
    val seenTypes = HashSet<Int>()
    var offset = start
    while (offset < body.size) {
        if (offset + 4 > body.size) throw DecodeErrorException("ServerHello extension header is truncated")
        val extensionType = readUint16(body, offset)
        val extensionLength = readUint16(body, offset + 2)
        offset += 4
        if (offset + extensionLength > body.size) throw DecodeErrorException("ServerHello extension is truncated")
        if (!seenTypes.add(extensionType)) throw DecodeErrorException("Duplicate ServerHello extension: $extensionType")
        extensions += extensionType to body.copyOfRange(offset, offset + extensionLength)
        offset += extensionLength
    }
    return extensions
}

private fun readUint16(bytes: ByteArray, offset: Int): Int =
    ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
