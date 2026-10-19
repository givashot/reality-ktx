package org.givashot.tls.record

import org.givashot.tls.connection.BadRecordMacException
import org.givashot.tls.connection.UnexpectMessageException
import org.givashot.tls.connection.UnexpectedContentTypeException
import org.givashot.tls.constant.TLS_AEAD_TAG_LENGTH
import org.givashot.tls.constant.TLS_CONTENT_TYPE_APPLICATION_DATA_
import org.givashot.tls.constant.TLS_CONTENT_TYPE_CCS
import org.givashot.tls.constant.TLS_MAX_CONSECUTIVE_EMPTY_RECORDS
import org.givashot.tls.crypto.TrafficKeys
import org.givashot.tls.crypto.decryptTlsRecord
import org.givashot.tls.crypto.encryptTlsRecord
import org.givashot.tls.crypto.tlsRecord
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

    fun feed(bytes: ByteArray): List<TlsRecordEvent> {
        if (bytes.isEmpty()) return emptyList()
        val tlsRecords = decoder.feed(bytes)
        return tlsRecords.map { tlsRecordMessage ->
            if (tlsRecordMessage.contentType == TLS_CONTENT_TYPE_CCS) {
                if (tlsRecordMessage.payload.size != 1 || tlsRecordMessage.payload[0] != 1.toByte()) {
                    throw UnexpectMessageException("malformed ChangeCipherSpec")
                }
                countEmptyRecord()
                return@map TlsRecordEvent.CompatibilityCcs
            }

            val type: Int
            val payload: ByteArray
            when (val readProtection = state.readProtection) {
                ReadProtection.Plaintext -> {
                    type = tlsRecordMessage.contentType
                    payload = tlsRecordMessage.payload
                }

                is ReadProtection.Encrypted -> {
                    if (tlsRecordMessage.contentType != TLS_CONTENT_TYPE_APPLICATION_DATA_) {
                        throw UnexpectedContentTypeException(
                            TLS_CONTENT_TYPE_APPLICATION_DATA_,
                            tlsRecordMessage.contentType,
                            "protected record"
                        )
                    }
                    val keys = readProtection.keys
                    val decrypted = try {
                        decryptTlsRecord(
                            tlsRecordMessage.encodedRecord,
                            keys.key,
                            keys.iv,
                            keys.sequenceNumber,
                            keys.cipherSuite
                        )
                    } catch (_: GeneralSecurityException) {
                        throw BadRecordMacException()
                    }
                    keys.sequenceNumber = checkedSequenceAfter(keys.sequenceNumber, 1)
                    type = decrypted.contentType
                    payload = decrypted.payload
                }
            }

            if (payload.isEmpty()) {
                countEmptyRecord()
                return@map TlsRecordEvent.Empty(type)
            }
            consecutiveEmptyRecords = 0
            return@map TlsRecordEvent.Content(type, payload)
        }
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
    }

    fun installWriteProtection(keys: TrafficKeys) {
        state.writeProtection = WriteProtection.Encrypted(keys)
    }

    fun updateReadKeys() {
        val protection = state.readProtection as? ReadProtection.Encrypted
            ?: throw IllegalStateException("Read protection is not installed")
        protection.keys.update()
    }

    fun updateWriteKeys() {
        val protection = state.writeProtection as? WriteProtection.Encrypted
            ?: throw IllegalStateException("Write protection is not installed")
        protection.keys.update()
    }

    private fun countEmptyRecord() {
        consecutiveEmptyRecords++
        if (consecutiveEmptyRecords > TLS_MAX_CONSECUTIVE_EMPTY_RECORDS) {
            throw UnexpectMessageException("More than $TLS_MAX_CONSECUTIVE_EMPTY_RECORDS consecutive empty records")
        }
    }

    fun encode(contentType: Int, payload: ByteArray, paddingLength: Int = 0): ByteArray {
        return when (val writeProtection = state.writeProtection) {
            WriteProtection.Plaintext -> {
                if (paddingLength > 0) {
                    throw IllegalArgumentException("paddingLength cannot working in plaintext phase")
                }
                tlsRecord(contentType, payload)
            }

            is WriteProtection.Encrypted -> {
                val writeKeys = writeProtection.keys
                val sequenceNumber = writeKeys.sequenceNumber
                val record = encryptTlsRecord(
                    contentType,
                    payload,
                    writeKeys.key,
                    writeKeys.iv,
                    sequenceNumber,
                    writeKeys.cipherSuite,
                    paddingLength
                )
                writeKeys.sequenceNumber = checkedSequenceAfter(writeKeys.sequenceNumber, 1)
                record
            }
        }
    }

    fun encode(contentType: Int, payload: ByteArray, recordLengths: List<Int>): List<ByteArray> {
        return when (val protection = state.writeProtection) {
            WriteProtection.Plaintext -> {
                throw IllegalArgumentException("recordLengths cannot working in plaintext phase")
            }
            is WriteProtection.Encrypted -> {
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
