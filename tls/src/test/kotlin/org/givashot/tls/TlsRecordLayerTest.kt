package org.givashot.tls

import org.givashot.tls.connection.TlsError
import org.givashot.tls.connection.TlsProtocolException
import org.givashot.tls.constant.TLS_CONTENT_TYPE_ALERT
import org.givashot.tls.constant.TLS_CONTENT_TYPE_APPLICATION_DATA_
import org.givashot.tls.constant.TLS_MAX_CONSECUTIVE_EMPTY_RECORDS
import org.givashot.tls.crypto.encryptTlsRecord
import org.givashot.tls.record.TlsRecordEvent
import org.givashot.tls.state.TlsAlert
import org.givashot.tls.constant.TLS_CONTENT_TYPE_CCS
import org.givashot.tls.constant.TLS_CONTENT_TYPE_HANDSHAKE
import org.givashot.tls.crypto.CipherSuite
import org.givashot.tls.crypto.TrafficKeys
import org.givashot.tls.crypto.tlsRecord
import org.givashot.tls.record.TlsRecordLayer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

class TlsRecordLayerTest {
    private val suite = CipherSuite.fromId(CipherSuite.TLS_AES_128_GCM_SHA256)
    private fun keys() = TrafficKeys(ByteArray(16) { 1 }, ByteArray(12) { 2 }, suite)

    private fun pair(): Pair<TlsRecordLayer, TlsRecordLayer> {
        val sender = TlsRecordLayer(4096).also { it.installWriteProtection(keys()) }
        val receiver = TlsRecordLayer(4096).also { it.installReadProtection(keys()) }
        return sender to receiver
    }

    @Test
    fun `plaintext encode produces a single record`() {
        val layer = TlsRecordLayer(4096)
        val records = layer.encode(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(1, 2, 3), listOf(100, 200))
        assertEquals(1, records.size)
        assertContentEquals(tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(1, 2, 3)), records.single())
    }

    @Test
    fun `encrypted records round trip and follow the length profile`() {
        val (sender, receiver) = pair()
        val payload = ByteArray(100) { it.toByte() }
        val records = sender.encode(TLS_CONTENT_TYPE_APPLICATION_DATA_, payload, listOf(64, 128))

        assertEquals(listOf(5 + 64, 5 + 128), records.map { it.size })
        val received = ArrayList<Byte>()
        records.forEach { receiver.feed(it) }
        while (true) {
            val event = receiver.nextEvent() ?: break
            received += content(event).payload.toList()
        }
        assertContentEquals(payload, received.toByteArray())
    }

    @Test
    fun `empty application payload encodes to nothing`() {
        val (sender, _) = pair()
        assertEquals(emptyList(), sender.encode(TLS_CONTENT_TYPE_APPLICATION_DATA_, ByteArray(0), listOf(64)))
    }

    @Test
    fun `profile too small for the plaintext is rejected`() {
        val (sender, _) = pair()
        assertFailsWith<IllegalArgumentException> {
            sender.encode(TLS_CONTENT_TYPE_HANDSHAKE, ByteArray(100), listOf(32))
        }
    }

    @Test
    fun `sequence numbers advance per record`() {
        val (sender, receiver) = pair()
        val first = sender.encode(TLS_CONTENT_TYPE_APPLICATION_DATA_, byteArrayOf(1), listOf(64)).single()
        val second = sender.encode(TLS_CONTENT_TYPE_APPLICATION_DATA_, byteArrayOf(2), listOf(64)).single()

        receiver.feed(second)
        assertFailsWith<Exception> { receiver.nextEvent() }

        val (_, fresh) = pair()
        fresh.feed(first + second)
        assertContentEquals(byteArrayOf(1), content(fresh.nextEvent()).payload)
        assertContentEquals(byteArrayOf(2), content(fresh.nextEvent()).payload)
    }

    @Test
    fun `events are handed out lazily one at a time`() {
        val layer = TlsRecordLayer(4096)
        layer.feed(
            tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(1)) + tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(2)),
        )
        assertContentEquals(byteArrayOf(1), content(layer.nextEvent()).payload)
        assertContentEquals(byteArrayOf(2), content(layer.nextEvent()).payload)
        assertNull(layer.nextEvent())
    }
    @Test
    fun `plaintext inbound bytes are captured until read protection is installed`() {
        val layer = TlsRecordLayer(4096)
        val hello = tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(1, 2, 3))
        layer.feed(hello.copyOfRange(0, 4))
        layer.feed(hello.copyOfRange(4, hello.size))
        assertContentEquals(hello, layer.plaintextInboundBytes())

        layer.reset()
        assertContentEquals(hello, layer.plaintextInboundBytes())

        layer.installReadProtection(keys())
        assertEquals(0, layer.plaintextInboundBytes().size)
    }

    @Test
    fun `plaintext capture is capped`() {
        val layer = TlsRecordLayer(64)
        val junk = ByteArray(1024) { 0x16 }
        assertFailsWith<Exception> { repeat(1000) { layer.feed(junk) } }
    }

    @Test
    fun `well formed change cipher spec is an event and malformed is rejected`() {
        val layer = TlsRecordLayer(4096)
        layer.feed(TestTlsClient.ccsRecord + tlsRecord(20, byteArrayOf(2)))
        assertEquals(TlsRecordEvent.CompatibilityCcs, layer.nextEvent())
        assertFailsWith<TlsProtocolException> { layer.nextEvent() }
    }

    @Test
    fun `change cipher spec does not consume a sequence number`() {
        val (sender, receiver) = pair()
        val record = sender.encode(TLS_CONTENT_TYPE_APPLICATION_DATA_, byteArrayOf(9), listOf(64)).single()
        receiver.feed(TestTlsClient.ccsRecord + record)
        assertEquals(TlsRecordEvent.CompatibilityCcs, receiver.nextEvent())
        assertContentEquals(byteArrayOf(9), content(receiver.nextEvent()).payload)
    }

    @Test
    fun `empty records are reported with their type`() {
        val layer = TlsRecordLayer(4096)
        layer.feed(tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, ByteArray(0)) + tlsRecord(TLS_CONTENT_TYPE_ALERT, ByteArray(0)))
        assertEquals(TlsRecordEvent.Empty(TLS_CONTENT_TYPE_HANDSHAKE), layer.nextEvent())
        assertEquals(TlsRecordEvent.Empty(TLS_CONTENT_TYPE_ALERT), layer.nextEvent())
    }

    @Test
    fun `encrypted empty records are counted per inner type`() {
        val receiver = TlsRecordLayer(4096).also { it.installReadProtection(keys()) }
        val types = listOf(TLS_CONTENT_TYPE_HANDSHAKE, TLS_CONTENT_TYPE_APPLICATION_DATA_, TLS_CONTENT_TYPE_ALERT)
        types.forEachIndexed { sequence, type ->
            val k = keys()
            receiver.feed(encryptTlsRecord(type, ByteArray(0), k.key, k.iv, sequence.toLong(), suite, 32))
        }
        types.forEach { assertEquals(TlsRecordEvent.Empty(it), receiver.nextEvent()) }
    }
    @Test
    fun `too many consecutive empty records or ccs fail and content resets the count`() {
        val layer = TlsRecordLayer(4096)
        val empty = tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, ByteArray(0))
        val content = tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(1))
        repeat(TLS_MAX_CONSECUTIVE_EMPTY_RECORDS) { layer.feed(empty) }
        repeat(TLS_MAX_CONSECUTIVE_EMPTY_RECORDS) { assertIs<TlsRecordEvent.Empty>(layer.nextEvent()) }
        layer.feed(content)
        assertIs<TlsRecordEvent.Content>(layer.nextEvent())

        repeat(TLS_MAX_CONSECUTIVE_EMPTY_RECORDS) { layer.feed(TestTlsClient.ccsRecord) }
        repeat(TLS_MAX_CONSECUTIVE_EMPTY_RECORDS) { assertEquals(TlsRecordEvent.CompatibilityCcs, layer.nextEvent()) }
        layer.feed(empty)
        val error = assertFailsWith<TlsProtocolException> { layer.nextEvent() }
        assertIs<TlsError.Peer.TooManyEmptyRecords>(error.error)
    }

    @Test
    fun `tampered record is bad_record_mac`() {
        val (sender, receiver) = pair()
        val record = sender.encode(TLS_CONTENT_TYPE_APPLICATION_DATA_, byteArrayOf(1), listOf(64)).single()
        record[record.size - 1] = (record[record.size - 1].toInt() xor 1).toByte()
        receiver.feed(record)
        val error = assertFailsWith<TlsProtocolException> { receiver.nextEvent() }
        assertEquals(TlsError.Peer.BadRecordMac, error.error)
    }

    @Test
    fun `all zero or unknown inner type is unexpected_message`() {
        val k = keys()
        listOf(0, TLS_CONTENT_TYPE_CCS).forEach { innerType ->
            val receiver = TlsRecordLayer(4096).also { it.installReadProtection(keys()) }
            receiver.feed(encryptTlsRecord(innerType, ByteArray(0), k.key, k.iv, 0, suite, 0))
            val error = assertFailsWith<TlsProtocolException> { receiver.nextEvent() }
            assertIs<TlsError.Peer.UnexpectedRecord>(error.error)
            assertEquals(TlsAlert.UNEXPECTED_MESSAGE, TlsAlert.forError(error.error))
        }
    }
    private fun content(event: TlsRecordEvent?) = assertIs<TlsRecordEvent.Content>(event)
}
