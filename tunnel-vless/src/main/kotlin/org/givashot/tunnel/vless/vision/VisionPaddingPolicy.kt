package org.givashot.tunnel.vless.vision

import org.givashot.tunnel.vless.const.VISION_MAX_CHUNK_SIZE
import org.givashot.tunnel.vless.const.VISION_MAX_FRAME_OVERHEAD
import java.util.random.RandomGenerator

/**
 * How much padding Vision adds to a frame, equivalent to Xray's `testseed`. It is a local choice that does not
 * appear on the wire, so it may differ between the two ends.
 *
 * Content shorter than [longPaddingThreshold] in long-padding mode (used while the inner TLS handshake is
 * running) gets `random(longPaddingRandomBound) + longPaddingBase - content` bytes, so that the frame hides its
 * content length; any other frame gets `random(shortPaddingRandomBound)` bytes.
 */
class VisionPaddingPolicy(
    val longPaddingThreshold: Int = 900,
    val longPaddingRandomBound: Int = 500,
    val longPaddingBase: Int = 900,
    val shortPaddingRandomBound: Int = 256,
) {

    init {
        require(longPaddingThreshold >= 0 && longPaddingBase >= 0) { "Padding thresholds must not be negative" }
        require(longPaddingRandomBound > 0 && shortPaddingRandomBound > 0) { "Padding random bounds must be positive" }
    }

    /** The padding length for a frame, never leaving the frame larger than [VISION_MAX_CHUNK_SIZE]. */
    fun paddingLength(contentLength: Int, longPadding: Boolean, random: RandomGenerator): Int {
        val length = if (contentLength < longPaddingThreshold && longPadding) {
            random.nextInt(longPaddingRandomBound) + longPaddingBase - contentLength
        } else {
            random.nextInt(shortPaddingRandomBound)
        }
        return length.coerceIn(0, maxOf(0, VISION_MAX_CHUNK_SIZE - VISION_MAX_FRAME_OVERHEAD - contentLength))
    }

    companion object {
        val DEFAULT = VisionPaddingPolicy()

        /** Builds a policy from Xray's `testseed` list; fewer than four values select [DEFAULT], as in Xray. */
        fun fromTestSeed(values: List<Int>?): VisionPaddingPolicy =
            if (values == null || values.size < 4) {
                DEFAULT
            } else {
                VisionPaddingPolicy(values[0], values[1], values[2], values[3])
            }
    }
}
