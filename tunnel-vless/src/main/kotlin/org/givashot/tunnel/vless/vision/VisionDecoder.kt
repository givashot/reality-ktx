package org.givashot.tunnel.vless.vision

import org.givashot.tls.record.ByteQueue
import org.givashot.tunnel.vless.const.*
import java.io.ByteArrayOutputStream

class VisionDecoder {

    private val buffered = ByteQueue()
    private var firstFrame = true

    var decoding = true

    var directRelay = false

    /**
     * Decodes all complete frames in [input], returning their content concatenated in frame order.
     */
    fun decode(input: ByteArray): ByteArray {
        check(decoding) { "when decode end or direct relay, cannot decode anymore" }
        buffered.append(input)
        val content = ByteArrayOutputStream()
        while (decoding) {
            val offset = if (firstFrame) VLESS_UUID_LENGTH else 0
            if (buffered.size < offset + VISION_FRAME_HEADER_LENGTH) break

            val command = buffered[offset].unsigned()
            val contentLength = (buffered[offset + 1].unsigned() shl 8) or
                    buffered[offset + 2].unsigned()
            val paddingLength = (buffered[offset + 3].unsigned() shl 8) or
                    buffered[offset + 4].unsigned()
            val frameLength = offset + VISION_FRAME_HEADER_LENGTH + contentLength + paddingLength
            if (buffered.size < frameLength) break

            val contentOffset = offset + VISION_FRAME_HEADER_LENGTH
            content.write(buffered.copyRange(contentOffset, contentOffset + contentLength))
            buffered.discard(frameLength)
            firstFrame = false

            when (command) {
                VISION_COMMAND_PADDING_CONTINUE -> Unit
                VISION_COMMAND_PADDING_END -> decoding = false
                VISION_COMMAND_PADDING_DIRECT -> {
                    decoding = false
                    directRelay = true
                }

                else -> throw IllegalArgumentException("Unknown Vision command: $command")
            }

            if (!decoding && buffered.size > 0) {
                throw IllegalArgumentException("Data follows terminal Vision frame")
            }
        }
        return content.toByteArray()
    }

    private fun Byte.unsigned(): Int = toInt() and 0xFF
}
