package org.givashot.tls.record

import org.givashot.tls.constant.TLS_AEAD_TAG_LENGTH
import org.givashot.tls.constant.TLS_APPLICATION_DATA_CONTENT_TYPE
import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE
import org.givashot.tls.crypto.ApplicationSecrets
import org.givashot.tls.crypto.HandshakeSecrets
import org.givashot.tls.crypto.decryptTlsRecord
import org.givashot.tls.crypto.encryptTlsRecord
import org.givashot.tls.crypto.tlsRecord
import org.givashot.tls.handshake.CipherSuite

internal sealed interface ReadProtection {
    data object Plaintext : ReadProtection
    data class Handshake(
        val trafficSecret: ByteArray,
        val key: ByteArray,
        val iv: ByteArray,
        val cipherSuite: CipherSuite,
        var sequence: Long,
    ) : ReadProtection
    data class Application(
        val trafficSecret: ByteArray,
        val key: ByteArray,
        val iv: ByteArray,
        val cipherSuite: CipherSuite,
        var sequence: Long,
    ) : ReadProtection
}

internal sealed interface WriteProtection {
    data object Plaintext : WriteProtection
    data class Handshake(
        val trafficSecret: ByteArray,
        val key: ByteArray,
        val iv: ByteArray,
        val cipherSuite: CipherSuite,
        var sequence: Long,
    ) : WriteProtection
    data class Application(
        val trafficSecret: ByteArray,
        val key: ByteArray,
        val iv: ByteArray,
        val cipherSuite: CipherSuite,
        var sequence: Long,
    ) : WriteProtection
}

internal class TlsRecordLayer(maxRecordSize: Int) {
    private val decoder = TlsRecordDecoder(maxRecordSize)
    private var readProtection: ReadProtection = ReadProtection.Plaintext
    private var writeProtection: WriteProtection = WriteProtection.Plaintext

    fun feed(bytes: ByteArray): List<TlsRecordMessage> = decoder.feed(bytes)

    fun reset() {
        decoder.reset()
        readProtection = ReadProtection.Plaintext
        writeProtection = WriteProtection.Plaintext
    }

    fun installHandshakeKeys(secrets: HandshakeSecrets) {
        readProtection = ReadProtection.Handshake(
            trafficSecret = secrets.clientHandshakeTrafficSecret,
            key = secrets.clientWriteKey,
            iv = secrets.clientWriteIv,
            cipherSuite = secrets.cipherSuite,
            sequence = 0L,
        )
        writeProtection = WriteProtection.Handshake(
            trafficSecret = secrets.serverHandshakeTrafficSecret,
            key = secrets.serverWriteKey,
            iv = secrets.serverWriteIv,
            cipherSuite = secrets.cipherSuite,
            sequence = 0L,
        )
    }

    fun installApplicationKeys(secrets: ApplicationSecrets) {
        readProtection = ReadProtection.Application(
            trafficSecret = secrets.clientAppTrafficSecret,
            key = secrets.clientWriteKey,
            iv = secrets.clientWriteIv,
            cipherSuite = secrets.cipherSuite,
            sequence = 0L,
        )
        writeProtection = WriteProtection.Application(
            trafficSecret = secrets.serverAppTrafficSecret,
            key = secrets.serverWriteKey,
            iv = secrets.serverWriteIv,
            cipherSuite = secrets.cipherSuite,
            sequence = 0L,
        )
    }

    fun decode(record: TlsRecordMessage): TlsPlaintext {
        return when (val protection = readProtection) {
            is ReadProtection.Plaintext -> TlsPlaintext(record.contentType, record.payload)
            is ReadProtection.Handshake -> {
                val plaintext = decryptProtected(record.encodedRecord, protection.key, protection.iv, protection.sequence, protection.cipherSuite)
                require(plaintext.contentType == TLS_HANDSHAKE_CONTENT_TYPE) { "Expected encrypted handshake record" }
                protection.sequence = checkedSequenceAfter(protection.sequence, 1)
                plaintext
            }
            is ReadProtection.Application -> {
                val plaintext = decryptProtected(record.encodedRecord, protection.key, protection.iv, protection.sequence, protection.cipherSuite)
                require(plaintext.contentType == TLS_APPLICATION_DATA_CONTENT_TYPE) { "Expected application data record" }
                protection.sequence = checkedSequenceAfter(protection.sequence, 1)
                plaintext
            }
        }
    }

    fun encode(contentType: Int, payload: ByteArray, recordLengths: List<Int>): List<ByteArray> {
        return when (val protection = writeProtection) {
            is WriteProtection.Plaintext -> listOf(tlsRecord(contentType, payload))
            is WriteProtection.Handshake -> {
                require(recordLengths.isNotEmpty()) { "TLS handshake record profile is empty" }
                val records = encryptRecords(
                    contentType = contentType,
                    plaintext = payload,
                    key = protection.key,
                    iv = protection.iv,
                    cipherSuite = protection.cipherSuite,
                    sequenceNumber = protection.sequence,
                    recordLengths = recordLengths,
                )
                protection.sequence = checkedSequenceAfter(protection.sequence, records.size)
                records
            }
            is WriteProtection.Application -> {
                if (payload.isEmpty()) return emptyList()
                require(recordLengths.isNotEmpty()) { "Application record profile is empty" }
                val records = encryptRecords(
                    contentType = contentType,
                    plaintext = payload,
                    key = protection.key,
                    iv = protection.iv,
                    cipherSuite = protection.cipherSuite,
                    sequenceNumber = protection.sequence,
                    recordLengths = recordLengths,
                )
                protection.sequence = checkedSequenceAfter(protection.sequence, records.size)
                records
            }
        }
    }

    private fun decryptProtected(
        encodedRecord: ByteArray,
        key: ByteArray,
        iv: ByteArray,
        sequence: Long,
        cipherSuite: CipherSuite,
    ): TlsPlaintext {
        val decrypted = decryptTlsRecord(encodedRecord, key, iv, sequence, cipherSuite)
        return TlsPlaintext(decrypted.contentType, decrypted.payload)
    }

    private fun encryptRecords(
        contentType: Int,
        plaintext: ByteArray,
        key: ByteArray,
        iv: ByteArray,
        cipherSuite: CipherSuite,
        sequenceNumber: Long,
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
        recordLengths.forEachIndexed { index, _ ->
            val capacity = capacities[index]
            val plainLength = minOf(capacity, plaintext.size - offset)
            val paddingLength = capacity - plainLength
            records += encryptTlsRecord(
                contentType = contentType,
                plaintext = plaintext.copyOfRange(offset, offset + plainLength),
                writeKey = key,
                writeIv = iv,
                sequenceNumber = checkedSequenceAfter(sequenceNumber, index),
                cipherSuite = cipherSuite,
                paddingLength = paddingLength,
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
