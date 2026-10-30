package org.givashot.tunnel.vless.vision

import org.givashot.tls.constant.TLS_AES_128_CCM_8_SHA256
import org.givashot.tls.constant.TLS_CONTENT_TYPE_CCS
import org.givashot.tls.constant.TLS_CONTENT_TYPE_HANDSHAKE
import org.givashot.tls.constant.TLS_HANDSHAKE_SERVER_HELLO_CONTENT_TYPE
import org.givashot.tls.constant.TLS_HANDSHAKE_SESSION_ID_OFFSET_BASE_BODY
import org.givashot.tls.handshake.HandshakeMessage
import org.givashot.tls.handshake.HandshakeMessageDecoder
import org.givashot.tls.record.TlsRecordDecoder
import org.givashot.tunnel.vless.const.VISION_COMMAND_PADDING_CONTINUE
import org.givashot.tunnel.vless.const.VISION_COMMAND_PADDING_DIRECT
import org.givashot.tunnel.vless.const.VISION_COMMAND_PADDING_END
import org.givashot.tunnel.vless.const.VISION_FRAME_HEADER_LENGTH
import org.givashot.tunnel.vless.const.VISION_MAX_PADDING_COUNT_NON_TLS_SERVER_SIDE
import org.givashot.tunnel.vless.const.VISION_MAX_PADDING_COUNT_OVER_TLS_SERVER_SIDE
import java.security.SecureRandom
import java.util.random.RandomGenerator

class VisionServerEncoder(
    uuid: ByteArray,
    private val policy: VisionPaddingPolicy = VisionPaddingPolicy.DEFAULT,
    private val random: RandomGenerator = SecureRandom(),
) {

    private var pendingUuid: ByteArray? = uuid

    private val tls13CipherSuites = 0x1301..0x1305

    private val tls13SupportedVersions = byteArrayOf(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)

    var encoding = true

    private val tlsRecordDecoder = TlsRecordDecoder()

    private val handshakeMessageDecoder = HandshakeMessageDecoder()

    private var tlsConnection: Boolean? = null

    private var paddingCount = 0

    /**
     * Support Direct relay, true when client and dest over tls 1.3 and not with TLS_AES_128_CCM_8_SHA256 cipher suites
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
                    handshakeMessages.firstOrNull { it.type == TLS_HANDSHAKE_SERVER_HELLO_CONTENT_TYPE }?.let {
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
        require(this.type == TLS_HANDSHAKE_SERVER_HELLO_CONTENT_TYPE) { "handshake message must be server hello" }
        val cipherSuiteOffset = TLS_HANDSHAKE_SESSION_ID_OFFSET_BASE_BODY +
                body[TLS_HANDSHAKE_SESSION_ID_OFFSET_BASE_BODY].unsigned() +
                1
        if (cipherSuiteOffset + 2 > body.size) return false
        val cipherSuite = (body[cipherSuiteOffset].unsigned() shl 8) or body[cipherSuiteOffset + 1].unsigned()
        if (cipherSuite in tls13CipherSuites && cipherSuite != TLS_AES_128_CCM_8_SHA256) {
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
            return body.contains(tls13SupportedVersions)
        }
        return false
    }

    private fun Byte.unsigned(): Int = toInt() and 0xFF

    private fun frame(content: ByteArray, command: Int, longPadding: Boolean): ByteArray {
        val paddingLength = policy.paddingLength(content.size, longPadding, random)
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