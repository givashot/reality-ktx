package org.givashot.tunnel.vless.vision

import java.util.random.RandomGenerator

class VisionPaddingPolicy(
    val longPaddingThreshold: Int = 800,
    val longPaddingBase: Int = 1000,
    val longPaddingRandomBound: Int = 400,
    val shortPaddingRandomBound: Int = 128,
    val nonPaddingThreshold: Int = longPaddingBase + longPaddingRandomBound
) {

    init {
        require(longPaddingThreshold >= 0 && longPaddingBase >= 0) { "Padding thresholds must not be negative" }
        require(longPaddingRandomBound > 0 && shortPaddingRandomBound > 0) { "Padding random bounds must be positive" }
        require(nonPaddingThreshold > 0) { "Non padding threshold must be positive" }
    }

    /**
     * The padding length for a frame
     */
    fun paddingLength(contentLength: Int, longPadding: Boolean, random: RandomGenerator): Int {
        return if (contentLength < nonPaddingThreshold) {
            if (contentLength < longPaddingThreshold && longPadding) {
                (longPaddingBase + random.nextInt(longPaddingRandomBound) - contentLength).coerceAtLeast(0)
            } else {
                random.nextInt(shortPaddingRandomBound)
            }
        } else {
            0
        }
    }

    companion object {
        val DEFAULT = VisionPaddingPolicy()

        fun fromTestSeed(values: List<Int>?): VisionPaddingPolicy =
            if (values == null || values.size < 4) {
                DEFAULT
            } else {
                VisionPaddingPolicy(values[0], values[1], values[2], values[3])
            }
    }
}
