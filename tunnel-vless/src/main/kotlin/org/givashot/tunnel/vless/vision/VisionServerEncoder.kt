package org.givashot.tunnel.vless.vision

import org.givashot.tls.connection.DecodeErrorException
import org.givashot.tls.constant.*
import org.givashot.tls.crypto.globalSecureRandom
import org.givashot.tls.handshake.HandshakeMessage
import org.givashot.tls.handshake.HandshakeMessageDecoder
import org.givashot.tls.handshake.parseServerHello
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

    private var detectedCCS = false

    fun encode(input: ByteArray): ByteArray {
        check(encoding) { "when encode end or direct relay, cannot encode anymore" }
        if (tlsConnection == false) {
            return paddingWhenNonTls(input)
        }
        try {
            val tlsRecords = tlsRecordDecoder.feed(input)
            var command = VISION_COMMAND_PADDING_CONTINUE
            if (tlsRecords.isNotEmpty()) {
                tlsConnection = true
                val handshakeMessages = arrayListOf<HandshakeMessage>()
                tlsRecords.forEach { tlsRecord ->
                    if (tlsRecord.contentType == TLS_CONTENT_TYPE_HANDSHAKE) {
                        handshakeMessages.addAll(handshakeMessageDecoder.feed(tlsRecord.payload))
                    }
                    if (tlsRecord.contentType == TLS_CONTENT_TYPE_CCS) {
                        detectedCCS = true
                    }
                }
                if (handshakeMessages.isNotEmpty()) {
                    handshakeMessages.firstOrNull { it.type == TLS_HANDSHAKE_CONTENT_TYPE_SERVER_HELLO }?.let {
                        if (supportDirectRelay == null) {
                            supportDirectRelay = it.supportDirectRelay()
                        }
                    }
                }
                paddingCount += tlsRecords.size
                val tls13CipherTextPhase = supportDirectRelay == true && detectedCCS
                if ((tls13CipherTextPhase || paddingCount >= VISION_MAX_PADDING_COUNT_OVER_TLS_SERVER_SIDE)
                    && tlsRecordDecoder.bufferSize() == 0
                ) {
                    // when tls13CipherTextPhase or paddingCount reached the max, and reached the boundary of tls record
                    // we do not padding anymore in the next frame
                    // in tls13CipherTextPhase case, means we're only padding the frame(contains server hello, ccs)
                    // the next frame normally are 0x17 tls record, and we do not padding
                    // most server response one tls record with a server flight(EE + CR + Certificate + CV + FINISHED) after server hello
                    // the server flight tls record are no observable length fingerprinter, so we do not padding
                    command = if (supportDirectRelay == true) {
                        VISION_COMMAND_PADDING_DIRECT
                    } else {
                        VISION_COMMAND_PADDING_END
                    }
                    tlsRecordDecoder.reset()
                    handshakeMessageDecoder.reset()
                    encoding = false
                }
            }
            return frame(input, command, true)
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
        val serverHello = try {
            parseServerHello()
        } catch (_: DecodeErrorException) {
            return false
        }
        return serverHello.cipherSuite != TLS_AES_128_CCM_8_SHA256
                && serverHello.cipherSuite in TLS13_CIPHER_SUITES
                && serverHello.isTls13
    }

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