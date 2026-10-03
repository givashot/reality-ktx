package org.givashot.tls.handshake

import org.givashot.tls.constant.TLS_HANDSHAKE_HEADER_LENGTH
import org.givashot.tls.record.ByteQueue

internal class HandshakeMessageDecoder(
    private val maxMessageLength: Int = 1024 * 64,
) {
    private val buffered = ByteQueue()

    val bufferedByteCount: Int
        get() = buffered.size

    init {
        require(maxMessageLength >= TLS_HANDSHAKE_HEADER_LENGTH)
    }

    fun feed(fragment: ByteArray): List<HandshakeMessage> {
        buffered.append(fragment)
        val messages = ArrayList<HandshakeMessage>()
        while (buffered.size >= TLS_HANDSHAKE_HEADER_LENGTH) {
            val bodyLength = ((buffered[1].toInt() and 0xFF) shl 16) or
                ((buffered[2].toInt() and 0xFF) shl 8) or
                (buffered[3].toInt() and 0xFF)
            val messageLength = TLS_HANDSHAKE_HEADER_LENGTH + bodyLength
            require(messageLength <= maxMessageLength) { "TLS handshake message exceeds maximum size limit" }
            if (buffered.size < messageLength) break

            val encoded = buffered.copyRange(0, messageLength)
            messages += HandshakeMessage(
                type = encoded[0].toInt() and 0xFF,
                body = encoded.copyOfRange(TLS_HANDSHAKE_HEADER_LENGTH, encoded.size),
                encodedBytes = encoded,
            )
            buffered.discard(messageLength)
        }
        return messages
    }

    fun reset() {
        buffered.clear()
    }
}
