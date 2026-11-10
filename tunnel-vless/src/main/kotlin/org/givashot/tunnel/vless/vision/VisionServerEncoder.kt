package org.givashot.tunnel.vless.vision

import org.givashot.tls.constant.*
import org.givashot.tls.crypto.globalSecureRandom
import org.givashot.tls.handshake.HandshakeMessage
import org.givashot.tls.handshake.HandshakeMessageDecoder
import org.givashot.tls.record.TlsRecordDecoder
import org.givashot.tunnel.vless.const.*

class VisionServerEncoder(
    uuid: ByteArray,
    private val policy: VisionPaddingPolicy = VisionPaddingPolicy.DEFAULT,
) {

    private var pendingUuid: ByteArray? = uuid

    var encoding = true

    private val tlsRecordDecoder = TlsRecordDecoder()

    private val handshakeMessageDecoder = HandshakeMessageDecoder()

    private var tlsConnection: Boolean? = null

    private var paddingCount = 0

    /**
     * Support Direct relay, true when client and dest over tls 1.3 and not with TLS_AES_128_CCM_8_SHA256 cipher suite
     */
    var supportDirectRelay: Boolean? = null

    fun encode(input: ByteArray): ByteArray {
        check(encoding) { "when encode end or direct relay, cannot encode anymore" }
        if (tlsConnection == false) {
            return paddingWhenNonTls(input)
        }
        try {
            val tlsRecords = tlsRecordDecoder.feed(input)
            if (tlsRecords.isNotEmpty()) {
                tlsConnection = true
                val handshakeMessages = arrayListOf<HandshakeMessage>()
                tlsRecords.forEach { tlsRecord ->
                    if (tlsRecord.contentType == TLS_CONTENT_TYPE_HANDSHAKE) {
                        handshakeMessages.addAll(handshakeMessageDecoder.feed(tlsRecord.payload))
                    }
                }
                if (handshakeMessages.isNotEmpty()) {
                    handshakeMessages.firstOrNull { it.type == TLS_HANDSHAKE_CONTENT_TYPE_SERVER_HELLO }?.let {
                        if (supportDirectRelay == null) {
                            supportDirectRelay = it.supportDirectRelay()
                        }
                    }
                }
                var command = VISION_COMMAND_PADDING_CONTINUE
                val ccsCount = tlsRecords.sumOf { tlsRecord ->
                    if (tlsRecord.contentType == TLS_CONTENT_TYPE_CCS) 1 else 0
                }
                paddingCount += (tlsRecords.size - ccsCount)
                if (paddingCount >= VISION_MAX_PADDING_COUNT_OVER_TLS_SERVER_SIDE) {
                    command = if (supportDirectRelay == true) {
                        VISION_COMMAND_PADDING_DIRECT
                    } else {
                        VISION_COMMAND_PADDING_END
                    }
                    tlsRecordDecoder.reset()
                    handshakeMessageDecoder.reset()
                    encoding = false
                }
                return frame(input, command, true)
            } else {
                return frame(input, VISION_COMMAND_PADDING_CONTINUE, true)
            }
        } catch (_: Exception) {
            // not a tls input
            tlsConnection = false
            return paddingWhenNonTls(input)
        }
    }

    private fun paddingWhenNonTls(input: ByteArray): ByteArray {
        paddingCount++
        var command = VISION_COMMAND_PADDING_CONTINUE
        if (paddingCount == VISION_MAX_PADDING_COUNT_NON_TLS_SERVER_SIDE) {
            command = VISION_COMMAND_PADDING_END
            encoding = false
        }
        return frame(input, command, false)
    }

    private fun HandshakeMessage.supportDirectRelay(): Boolean {
        require(this.type == TLS_HANDSHAKE_CONTENT_TYPE_SERVER_HELLO) { "handshake message must be server hello" }
        val cipherSuiteOffset = TLS_HANDSHAKE_SESSION_ID_OFFSET_BASE_BODY +
                body[TLS_HANDSHAKE_SESSION_ID_OFFSET_BASE_BODY].unsigned() +
                1
        if (cipherSuiteOffset + 2 > body.size) return false
        val cipherSuite = (body[cipherSuiteOffset].unsigned() shl 8) or body[cipherSuiteOffset + 1].unsigned()
        if (cipherSuite in TLS13_CIPHER_SUITES && cipherSuite != TLS_AES_128_CCM_8_SHA256) {
            fun ByteArray.contains(another: ByteArray): Boolean {
                for (i in indices) {
                    if (this[i] == another[0]) {
                        for (j in 1 until another.size) {
                            if (this[i + j] == another[j]) {
                                if (j == another.size - 1) {
                                    return true
                                }
                            } else {
                                break
                            }
                        }
                    }
                }
                return false
            }
            return body.contains(TLS13_SUPPORTED_VERSIONS)
        }
        return false
    }

    private fun Byte.unsigned(): Int = toInt() and 0xFF

    private fun frame(content: ByteArray, command: Int, longPadding: Boolean): ByteArray {
        val paddingLength = policy.paddingLength(content.size, longPadding, globalSecureRandom)
        val uuid = pendingUuid
        pendingUuid = null
        val uuidLength = uuid?.size ?: 0
        val frame = ByteArray(uuidLength + VISION_FRAME_HEADER_LENGTH + content.size + paddingLength)
        uuid?.copyInto(frame)
        var offset = uuidLength
        frame[offset++] = command.toByte()
        frame[offset++] = (content.size ushr 8).toByte()
        frame[offset++] = content.size.toByte()
        frame[offset++] = (paddingLength ushr 8).toByte()
        frame[offset++] = paddingLength.toByte()
        content.copyInto(frame, offset)
        return frame
    }

}