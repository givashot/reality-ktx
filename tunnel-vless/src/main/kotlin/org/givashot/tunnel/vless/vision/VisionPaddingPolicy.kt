package org.givashot.tunnel.vless.vision

import java.util.random.RandomGenerator

class VisionPaddingPolicy(
    val longPaddingThreshold: Int = 1000,
    val longPaddingBase: Int = 1400,
    val longPaddingRandomBound: Int = 800,
    val shortPaddingRandomBound: Int = 128,
    val nonPaddingThreshold: Int = 2048
) {

    init {
        require(longPaddingThreshold > 0) { "Long Padding thresholds must be positive" }
        require(longPaddingBase > 0) { "Long Padding Base must be positive" }
        require(longPaddingBase > longPaddingThreshold) { "Long Padding base must greater than threshold" }
        require(longPaddingRandomBound > 0 && shortPaddingRandomBound > 0) { "Padding random bounds must be positive" }
        require(nonPaddingThreshold > 0) { "Non padding threshold must be positive" }
    }

    /**
     * The padding length for a frame
     */
    fun paddingLength(contentLength: Int, longPadding: Boolean, random: RandomGenerator): Int {
        return if (contentLength < nonPaddingThreshold) {
            if (contentLength < longPaddingThreshold && longPadding) {
                longPaddingBase + random.nextInt(longPaddingRandomBound) - contentLength
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
