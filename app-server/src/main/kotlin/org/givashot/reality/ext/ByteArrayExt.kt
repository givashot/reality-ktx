package org.givashot.reality.ext

/**
 * Converts the hex byte array padded on the receiver [String]
 *
 * @param targetByteLength the target byte length
 * @return the byte array
 */
fun String.toHexByteArrayPadded(targetByteLength: Int = 8): ByteArray {
    return this.trim()
        .take(targetByteLength * 2)
        .padEnd(targetByteLength * 2, '0')
        .hexToByteArray(HexFormat.Default)
}