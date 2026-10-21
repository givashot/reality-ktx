package org.givashot.tls.record

import org.givashot.tls.connection.BadRecordMacException
import org.givashot.tls.connection.UnexpectMessageException
import org.givashot.tls.connection.UnexpectedContentTypeException
import org.givashot.tls.connection.UnexpectedRecordException
import org.givashot.tls.constant.*
import org.givashot.tls.crypto.CipherSuite
import org.givashot.tls.crypto.TrafficKeys
import java.security.GeneralSecurityException
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * TLS record framing, protection, and the per-direction keys and sequence numbers in [RecordState].
 * Knows nothing about handshake phases, and neither interprets KeyUpdate nor derives keys.
 */
internal class TlsRecordLayer(
    maxRecordSize: Int,
) {

    private val state: RecordState = RecordState()
    private val decoder = TlsRecordDecoder(maxRecordSize)
    private val pendingRecords = ArrayDeque<TlsRecordMessage>()
    private var consecutiveEmptyRecords = 0

    /** Buffers inbound bytes and frames them into records. Nothing is decrypted until [readNext]. */
    fun feed(bytes: ByteArray) {
        if (bytes.isEmpty()) return
        pendingRecords.addAll(decoder.feed(bytes))
    }

    /**
     * Decrypts and returns the next buffered record, or null when none is complete. One record at a time, so the
     * caller can switch read keys (Finished, KeyUpdate) before the following record is decrypted.
     */
    fun readNext(): TlsRecordEvent? {
        val tlsRecordMessage = pendingRecords.pollFirst() ?: return null
        if (tlsRecordMessage.contentType == TLS_CONTENT_TYPE_CCS) {
            if (tlsRecordMessage.payload.size != 1 || tlsRecordMessage.payload[0] != 1.toByte()) {
                throw UnexpectMessageException("malformed ChangeCipherSpec")
            }
            countEmptyRecord()
            return TlsRecordEvent.CompatibilityCcs
        }

        val contentType: Int
        val payload: ByteArray
        when (val readProtection = state.readProtection) {
            ReadProtection.Plaintext -> {
                contentType = tlsRecordMessage.contentType
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
                        readProtection.sequenceNumber,
                        keys.cipherSuite
                    )
                } catch (_: GeneralSecurityException) {
                    throw BadRecordMacException()
                }
                readProtection.sequenceNumber = checkedSequenceAfter(readProtection.sequenceNumber, 1)
                contentType = decrypted.first
                payload = decrypted.second
            }
        }

        if (payload.isEmpty()) {
            countEmptyRecord()
            return TlsRecordEvent.Empty(contentType)
        }
        consecutiveEmptyRecords = 0
        return TlsRecordEvent.Content(contentType, payload)
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

    /** Current read keys; the caller derives the next generation and hands it back via [updateReadKeys]. */
    val readKeys: TrafficKeys
        get() = (state.readProtection as? ReadProtection.Encrypted)?.keys
            ?: throw IllegalStateException("Read protection is not installed")

    val writeKeys: TrafficKeys
        get() = (state.writeProtection as? WriteProtection.Encrypted)?.keys
            ?: throw IllegalStateException("Write protection is not installed")

    /** Switches to already derived keys; the read sequence number restarts at zero. */
    fun updateReadKeys(next: TrafficKeys) {
        check(state.readProtection is ReadProtection.Encrypted) { "Read protection is not installed" }
        state.readProtection = ReadProtection.Encrypted(next)
    }

    /** Switches to already derived keys; the write sequence number restarts at zero. */
    fun updateWriteKeys(next: TrafficKeys) {
        check(state.writeProtection is WriteProtection.Encrypted) { "Write protection is not installed" }
        state.writeProtection = WriteProtection.Encrypted(next)
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
                val keys = writeProtection.keys
                val record = encryptTlsRecord(
                    contentType,
                    payload,
                    keys.key,
                    keys.iv,
                    writeProtection.sequenceNumber,
                    keys.cipherSuite,
                    paddingLength
                )
                writeProtection.sequenceNumber = checkedSequenceAfter(writeProtection.sequenceNumber, 1)
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
                val records = encryptRecords(contentType, payload, protection, recordLengths)
                protection.sequenceNumber = checkedSequenceAfter(protection.sequenceNumber, records.size)
                records
            }
        }
    }

    private fun encryptRecords(
        contentType: Int,
        plaintext: ByteArray,
        protection: WriteProtection.Encrypted,
        recordLengths: List<Int>,
    ): List<ByteArray> {
        val keys = protection.keys
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
                sequenceNumber = checkedSequenceAfter(protection.sequenceNumber, index),
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

    private fun tlsRecord(contentType: Int, payload: ByteArray): ByteArray {
        require(contentType in 0..255 && payload.size <= 0xFFFF)
        return byteArrayOf(
            contentType.toByte(),
            TLS_RECORD_VERSION_HIGH.toByte(),
            TLS_RECORD_VERSION_LOW.toByte(),
            (payload.size ushr 8).toByte(),
            payload.size.toByte(),
        ) + payload
    }

    private fun encryptTlsRecord(
        contentType: Int,
        plaintext: ByteArray,
        writeKey: ByteArray,
        writeIv: ByteArray,
        sequenceNumber: Long,
        cipherSuite: CipherSuite,
        paddingLength: Int = 0,
    ): ByteArray {
        require(sequenceNumber >= 0)
        require(paddingLength >= 0)
        val inner = plaintext + contentType.toByte() + ByteArray(paddingLength)
        val ciphertextLength = TLS_AEAD_TAG_LENGTH + inner.size
        require(ciphertextLength <= 0xFFFF) { "TLS ciphertext record is too large" }
        val header = byteArrayOf(
            TLS_CONTENT_TYPE_APPLICATION_DATA_.toByte(),
            TLS_RECORD_VERSION_HIGH.toByte(),
            TLS_RECORD_VERSION_LOW.toByte(),
            (ciphertextLength ushr 8).toByte(),
            ciphertextLength.toByte(),
        )
        val nonce = writeIv.copyOf().also { value ->
            for (index in 0 until Long.SIZE_BYTES) {
                value[value.size - 1 - index] =
                    (value[value.size - 1 - index].toInt() xor (sequenceNumber ushr (index * 8)).toInt()).toByte()
            }
        }
        val cipher = createAeadCipher(Cipher.ENCRYPT_MODE, writeKey, nonce, cipherSuite)
        cipher.updateAAD(header)
        return header + cipher.doFinal(inner)
    }

    private fun decryptTlsRecord(
        record: ByteArray,
        writeKey: ByteArray,
        writeIv: ByteArray,
        sequenceNumber: Long,
        cipherSuite: CipherSuite,
    ): Pair<Int, ByteArray> {
        require(record.size >= 5 + TLS_AEAD_TAG_LENGTH + 1)
        require(record[0].toInt() and 0xFF == TLS_CONTENT_TYPE_APPLICATION_DATA_)
        require(record[1].toInt() and 0xFF == TLS_RECORD_VERSION_HIGH)
        require(record[2].toInt() and 0xFF == TLS_RECORD_VERSION_LOW)
        val length = ((record[3].toInt() and 0xFF) shl 8) or (record[4].toInt() and 0xFF)
        require(length == record.size - 5)

        val header = record.copyOfRange(0, 5)
        val ciphertext = record.copyOfRange(5, record.size)
        val nonce = writeIv.copyOf().also { value ->
            for (index in 0 until Long.SIZE_BYTES) {
                value[value.size - 1 - index] =
                    (value[value.size - 1 - index].toInt() xor (sequenceNumber ushr (index * 8)).toInt()).toByte()
            }
        }
        val cipher = createAeadCipher(Cipher.DECRYPT_MODE, writeKey, nonce, cipherSuite)
        cipher.updateAAD(header)
        val inner = cipher.doFinal(ciphertext)
        var contentEnd = inner.size - 1
        while (contentEnd >= 0 && inner[contentEnd].toInt() == 0) contentEnd--
        // RFC 8446 section 5.4: an all-zero inner plaintext or an unknown inner type is unexpected_message.
        if (contentEnd < 0) throw UnexpectedRecordException(0, "protected record")
        val contentType = inner[contentEnd].toInt() and 0xFF
        if (contentType != TLS_CONTENT_TYPE_HANDSHAKE &&
            contentType != TLS_CONTENT_TYPE_APPLICATION_DATA_ &&
            contentType != TLS_CONTENT_TYPE_ALERT
        ) {
            throw UnexpectedRecordException(contentType, "protected record")
        }
        return contentType to inner.copyOfRange(0, contentEnd)
    }

    private fun createAeadCipher(
        mode: Int,
        key: ByteArray,
        nonce: ByteArray,
        cipherSuite: CipherSuite,
    ): Cipher {
        val cipher = Cipher.getInstance(cipherSuite.aead)
        val keySpec = SecretKeySpec(key, if (cipherSuite.aead.startsWith("AES")) "AES" else "ChaCha20")
        if (cipherSuite.aead.startsWith("AES")) {
            cipher.init(mode, keySpec, GCMParameterSpec(cipherSuite.tagLen * 8, nonce))
        } else {
            cipher.init(mode, keySpec, IvParameterSpec(nonce))
        }
        return cipher
    }
    
}
