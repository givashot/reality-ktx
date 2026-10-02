package org.givashot.tls

internal class ByteQueue(initialCapacity: Int = 256) {
    private var bytes = ByteArray(initialCapacity)
    private var readIndex = 0
    private var writeIndex = 0

    val size: Int
        get() = writeIndex - readIndex

    operator fun get(index: Int): Byte {
        require(index in 0 until size)
        return bytes[readIndex + index]
    }

    fun append(input: ByteArray) {
        if (input.isEmpty()) return
        ensureCapacity(input.size)
        input.copyInto(bytes, writeIndex)
        writeIndex += input.size
    }

    fun copyRange(start: Int, endExclusive: Int): ByteArray {
        require(start in 0..size && endExclusive in start..size)
        return bytes.copyOfRange(readIndex + start, readIndex + endExclusive)
    }

    fun discard(count: Int) {
        require(count in 0..size)
        readIndex += count
        if (readIndex == writeIndex) {
            readIndex = 0
            writeIndex = 0
        }
    }

    fun clear() {
        readIndex = 0
        writeIndex = 0
    }

    private fun ensureCapacity(additional: Int) {
        if (bytes.size - writeIndex >= additional) return

        val currentSize = size
        if (bytes.size - currentSize >= additional) {
            bytes.copyInto(bytes, 0, readIndex, writeIndex)
            readIndex = 0
            writeIndex = currentSize
            return
        }

        val requiredCapacity = currentSize + additional
        var newCapacity = bytes.size.coerceAtLeast(1)
        while (newCapacity < requiredCapacity) {
            newCapacity = (newCapacity.toLong() * 2)
                .coerceAtMost(Int.MAX_VALUE.toLong())
                .toInt()
            require(newCapacity >= requiredCapacity) {
                "TLS input buffer is too large"
            }
        }
        val expanded = ByteArray(newCapacity)
        bytes.copyInto(expanded, 0, readIndex, writeIndex)
        bytes = expanded
        readIndex = 0
        writeIndex = currentSize
    }
}
