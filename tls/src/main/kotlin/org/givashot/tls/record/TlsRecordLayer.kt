package org.givashot.tls.record

import org.givashot.tls.constant.TLS_AEAD_TAG_LENGTH
import org.givashot.tls.constant.TLS_CONTENT_TYPE_APPLICATION_DATA_
import org.givashot.tls.constant.TLS_CONTENT_TYPE_CCS
import org.givashot.tls.constant.TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH
import org.givashot.tls.constant.TLS_MAX_CONSECUTIVE_EMPTY_RECORDS
import org.givashot.tls.connection.TlsError
import org.givashot.tls.connection.TlsProtocolException
import org.givashot.tls.crypto.TrafficKeys
import org.givashot.tls.crypto.decryptTlsRecord
import org.givashot.tls.crypto.encryptTlsRecord
import org.givashot.tls.crypto.tlsRecord
import java.io.ByteArrayOutputStream
import java.security.GeneralSecurityException
import java.util.*

/** TLS record framing, protection and the current read/write [RecordState]. Knows nothing about handshake phases. */
internal class TlsRecordLayer(
    maxRecordSize: Int,
) {

    private val state: RecordState = RecordState()
    private val decoder = TlsRecordDecoder(maxRecordSize)
    private val pendingRecords = ArrayDeque<TlsRecordMessage>()
    private var consecutiveEmptyRecords = 0

    private val plaintextInboundLimit = TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH + 2 * maxRecordSize
    private val plaintextInbound = ByteArrayOutputStream()
    private var capturingPlaintextInbound = true

    /** Every byte received while reads are still plaintext, kept so an unauthenticated connection can be replayed. */
    fun plaintextInboundBytes(): ByteArray = plaintextInbound.toByteArray()

    fun feed(bytes: ByteArray) {
        if (bytes.isEmpty()) return
        if (capturingPlaintextInbound) {
            plaintextInbound.write(bytes)
            require(plaintextInbound.size() <= plaintextInboundLimit) { "Plaintext TLS input exceeds limit" }
        }
        pendingRecords.addAll(decoder.feed(bytes))
    }

    fun reset() {
        decoder.reset()
        pendingRecords.clear()
        state.readProtection = ReadProtection.Plaintext
        state.writeProtection = WriteProtection.Plaintext
        consecutiveEmptyRecords = 0
    }

    fun installReadProtection(keys: TrafficKeys) {
        state.readProtection = ReadProtection.Encrypted(keys)
        capturingPlaintextInbound = false
        plaintextInbound.reset()
    }

    fun installWriteProtection(keys: TrafficKeys) {
        state.writeProtection = WriteProtection.Encrypted(keys)
    }

    /**
     * Next inbound record as an event, or null when none is queued. Decrypted lazily because the read keys are
     * installed mid-connection. Empty records and CCS count towards [TLS_MAX_CONSECUTIVE_EMPTY_RECORDS]
     * (BoringSSL behaviour); any non-empty record resets the count.
     */
    fun nextEvent(): TlsRecordEvent? {
        val record = pendingRecords.pollFirst() ?: return null
        if (record.contentType == TLS_CONTENT_TYPE_CCS) {
            if (record.payload.size != 1 || record.payload[0] != 1.toByte()) {
                throw TlsProtocolException(TlsError.Peer.InvalidChangeCipherSpec("malformed ChangeCipherSpec"))
            }
            countEmptyRecord()
            return TlsRecordEvent.CompatibilityCcs
        }

        val type: Int
        val payload: ByteArray
        when (val protection = state.readProtection) {
            ReadProtection.Plaintext -> {
                type = record.contentType
                payload = record.payload
            }

            is ReadProtection.Encrypted -> {
                if (record.contentType != TLS_CONTENT_TYPE_APPLICATION_DATA_) {
                    throw TlsProtocolException(
                        TlsError.Peer.UnexpectedContentType(
                            TLS_CONTENT_TYPE_APPLICATION_DATA_,
                            record.contentType,
                            "protected record"
                        ),
                    )
                }
                val keys = protection.keys
                val decrypted = try {
                    decryptTlsRecord(record.encodedRecord, keys.key, keys.iv, keys.sequenceNumber, keys.cipherSuite)
                } catch (_: GeneralSecurityException) {
                    throw TlsProtocolException(TlsError.Peer.BadRecordMac)
                }
                keys.sequenceNumber = checkedSequenceAfter(keys.sequenceNumber, 1)
                type = decrypted.contentType
                payload = decrypted.payload
            }
        }

        if (payload.isEmpty()) {
            countEmptyRecord()
            return TlsRecordEvent.Empty(type)
        }
        consecutiveEmptyRecords = 0
        return TlsRecordEvent.Content(type, payload)
    }

    private fun countEmptyRecord() {
        consecutiveEmptyRecords++
        if (consecutiveEmptyRecords > TLS_MAX_CONSECUTIVE_EMPTY_RECORDS) {
            throw TlsProtocolException(TlsError.Peer.TooManyEmptyRecords(TLS_MAX_CONSECUTIVE_EMPTY_RECORDS))
        }
    }

    fun encode(contentType: Int, payload: ByteArray, recordLengths: List<Int>): List<ByteArray> {
        return when (val protection = state.writeProtection) {
            WriteProtection.Plaintext -> listOf(tlsRecord(contentType, payload))
            is WriteProtection.Encrypted -> {
                if (payload.isEmpty() && contentType == TLS_CONTENT_TYPE_APPLICATION_DATA_) return emptyList()
                require(recordLengths.isNotEmpty()) { "TLS record length profile is empty" }
                val keys = protection.keys
                val records = encryptRecords(contentType, payload, keys, recordLengths)
                keys.sequenceNumber = checkedSequenceAfter(keys.sequenceNumber, records.size)
                records
            }
        }
    }

    private fun encryptRecords(
        contentType: Int,
        plaintext: ByteArray,
        keys: TrafficKeys,
        recordLengths: List<Int>,
    ): List<ByteArray> {
        val capacities = recordLengths.map { targetLength ->
            require(targetLength in (TLS_AEAD_TAG_LENGTH + 1)..0xFFFF) {
                "Invalid encrypted TLS record payload length: $targetLength"
            }
            targetLength - TLS_AEAD_TAG_LENGTH - 1
        }
        require(capacities.sumOf { it.toLong() } >= plaintext.size.toLong()) {
            "TLS record profile cannot contain the plaintext"
        }

        val records = ArrayList<ByteArray>(recordLengths.size)
        var offset = 0
        capacities.forEachIndexed { index, capacity ->
            val plainLength = minOf(capacity, plaintext.size - offset)
            records += encryptTlsRecord(
                contentType = contentType,
                plaintext = plaintext.copyOfRange(offset, offset + plainLength),
                writeKey = keys.key,
                writeIv = keys.iv,
                sequenceNumber = checkedSequenceAfter(keys.sequenceNumber, index),
                cipherSuite = keys.cipherSuite,
                paddingLength = capacity - plainLength,
            )
            offset += plainLength
        }
        check(offset == plaintext.size)
        return records
    }

    private fun checkedSequenceAfter(current: Long, count: Int): Long {
        require(count >= 0 && current <= Long.MAX_VALUE - count) { "TLS record sequence number overflow" }
        return current + count
    }
}
