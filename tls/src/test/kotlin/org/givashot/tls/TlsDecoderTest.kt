package org.givashot.tls

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertContentEquals
import org.givashot.tls.constant.TLS_CONTENT_TYPE_HANDSHAKE
import org.givashot.tls.crypto.tlsRecord
import org.givashot.tls.handshake.HandshakeMessage
import org.givashot.tls.handshake.HandshakeMessageDecoder
import org.givashot.tls.record.TlsRecordDecoder

class TlsDecoderTest {
    @Test
    fun `record decoder retains split headers and bodies`() {
        val encoded = tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(1, 2, 3, 4))
        val decoder = TlsRecordDecoder()

        assertEquals(emptyList(), decoder.feed(encoded.copyOfRange(0, 3)))
        assertEquals(emptyList(), decoder.feed(encoded.copyOfRange(3, 7)))
        val decoded = decoder.feed(encoded.copyOfRange(7, encoded.size))

        assertEquals(1, decoded.size)
        assertEquals(TLS_CONTENT_TYPE_HANDSHAKE, decoded.single().contentType)
        assertContentEquals(byteArrayOf(1, 2, 3, 4), decoded.single().payload)
        assertContentEquals(encoded, decoded.single().encodedRecord)
    }

    @Test
    fun `record decoder emits multiple records from one input`() {
        val first = tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(1))
        val second = tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(2, 3))
        val decoded = TlsRecordDecoder().feed(first + second)

        assertEquals(2, decoded.size)
        assertContentEquals(byteArrayOf(1), decoded[0].payload)
        assertContentEquals(byteArrayOf(2, 3), decoded[1].payload)
    }

    @Test
    fun `record decoder rejects unsupported content types`() {
        assertFailsWith<IllegalArgumentException> {
            TlsRecordDecoder().feed(tlsRecord(99, byteArrayOf()))
        }
    }

    @Test
    fun `handshake decoder joins fragments and splits coalesced messages`() {
        val first = byteArrayOf(1, 0, 0, 3, 10)
        val second = byteArrayOf(11, 12) + byteArrayOf(20, 0, 0, 1, 42)
        val decoder = HandshakeMessageDecoder()

        assertEquals(emptyList(), decoder.feed(first))
        val messages = decoder.feed(second)

        assertEquals(2, messages.size)
        assertEquals(1, messages[0].type)
        assertContentEquals(byteArrayOf(10, 11, 12), messages[0].body)
        assertContentEquals(byteArrayOf(20, 0, 0, 1, 42), messages[1].encodedBytes)
    }

    @Test
    fun `handshake decoder enforces message size limit`() {
        val decoder = HandshakeMessageDecoder(maxMessageLength = 5)
        assertFailsWith<IllegalArgumentException> {
            decoder.feed(byteArrayOf(1, 0, 0, 2, 1, 2))
        }
    }

    @Test
    fun `handshake message model preserves encoded bytes`() {
        val encoded = byteArrayOf(20, 0, 0, 1, 7)
        val message = HandshakeMessage(20, byteArrayOf(7), encoded)
        assertContentEquals(encoded, message.encodedBytes)
    }
}
