package org.givashot.tls

import org.givashot.tls.constant.TLS_CONTENT_TYPE_APPLICATION_DATA_
import org.givashot.tls.constant.TLS_CONTENT_TYPE_HANDSHAKE
import org.givashot.tls.crypto.CipherSuite
import org.givashot.tls.crypto.TrafficKeys
import org.givashot.tls.crypto.tlsRecord
import org.givashot.tls.record.TlsRecordLayer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

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
            val record = receiver.nextRecord() ?: break
            received += receiver.decode(record).payload.toList()
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
        assertFailsWith<Exception> { receiver.decode(receiver.nextRecord()!!) }

        val (_, fresh) = pair()
        fresh.feed(first + second)
        assertContentEquals(byteArrayOf(1), fresh.decode(fresh.nextRecord()!!).payload)
        assertContentEquals(byteArrayOf(2), fresh.decode(fresh.nextRecord()!!).payload)
    }

    @Test
    fun `records are handed out lazily one at a time`() {
        val layer = TlsRecordLayer(4096)
        layer.feed(
            tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(1)) + tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(2)),
        )
        assertContentEquals(byteArrayOf(1), layer.nextRecord()!!.payload)
        assertContentEquals(byteArrayOf(2), layer.nextRecord()!!.payload)
        assertNull(layer.nextRecord())
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
    fun `change cipher spec is accepted once and only when well formed`() {
        val layer = TlsRecordLayer(4096)
        layer.feed(TestTlsClient.ccsRecord + TestTlsClient.ccsRecord + tlsRecord(20, byteArrayOf(2)))
        val first = assertNotNull(layer.nextRecord())
        val second = assertNotNull(layer.nextRecord())
        val bad = assertNotNull(layer.nextRecord())

        assertTrue(layer.isChangeCipherSpec(first))
        assertTrue(layer.dropChangeCipherSpec(first))
        assertFalse(layer.dropChangeCipherSpec(second))
        assertFalse(TlsRecordLayer(4096).dropChangeCipherSpec(bad))
    }

    @Test
    fun `dropping change cipher spec does not consume a sequence number`() {
        val (sender, receiver) = pair()
        val record = sender.encode(TLS_CONTENT_TYPE_APPLICATION_DATA_, byteArrayOf(9), listOf(64)).single()
        receiver.feed(TestTlsClient.ccsRecord + record)
        assertTrue(receiver.dropChangeCipherSpec(receiver.nextRecord()!!))
        assertContentEquals(byteArrayOf(9), receiver.decode(receiver.nextRecord()!!).payload)
    }
}
