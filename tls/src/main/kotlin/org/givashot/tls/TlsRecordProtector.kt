package org.givashot.tls

import org.givashot.tls.constant.TLS_AEAD_TAG_LENGTH
import org.givashot.tls.constant.TLS_APPLICATION_DATA_CONTENT_TYPE
import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE
import org.givashot.tls.entity.ApplicationSecrets
import org.givashot.tls.entity.handshake.CipherSuite
import org.givashot.tls.entity.handshake.HandshakeSecrets

/** Owns traffic-key use and record sequence numbers for one TLS connection. */
internal class TlsRecordProtector {
    private var clientHandshakeSequenceNumber = 0L
    private var serverHandshakeSequenceNumber = 0L
    private var clientApplicationSequenceNumber = 0L
    private var serverApplicationSequenceNumber = 0L

    fun encryptHandshakeFlight(
        flight: ByteArray,
        secrets: HandshakeSecrets,
        recordLengths: List<Int>,
    ): List<ByteArray> {
        require(recordLengths.isNotEmpty()) { "TLS handshake record profile is empty" }
        val records = encryptProfiled(
            contentType = TLS_HANDSHAKE_CONTENT_TYPE,
            plaintext = flight,
            key = secrets.serverWriteKey,
            iv = secrets.serverWriteIv,
            cipherSuite = secrets.cipherSuite,
            sequenceNumber = serverHandshakeSequenceNumber,
            recordLengths = recordLengths,
        )
        serverHandshakeSequenceNumber = checkedSequenceAfter(serverHandshakeSequenceNumber, records.size)
        return records
    }

    fun decryptHandshakeRecord(record: ByteArray, secrets: HandshakeSecrets): ByteArray {
        val plaintext = decryptHandshakeRecord(record, secrets, clientHandshakeSequenceNumber)
        clientHandshakeSequenceNumber = checkedSequenceAfter(clientHandshakeSequenceNumber, 1)
        return plaintext
    }

    fun decryptApplicationRecord(record: ByteArray, secrets: ApplicationSecrets): ByteArray {
        val plaintext = decryptApplicationData(record, secrets, clientApplicationSequenceNumber)
        clientApplicationSequenceNumber = checkedSequenceAfter(clientApplicationSequenceNumber, 1)
        return plaintext
    }

    fun encryptApplicationData(
        plaintext: ByteArray,
        secrets: ApplicationSecrets,
        recordLengths: List<Int>,
    ): List<ByteArray> {
        if (plaintext.isEmpty()) return emptyList()
        require(recordLengths.isNotEmpty()) { "Application record profile is empty" }
        val records = encryptProfiled(
            contentType = TLS_APPLICATION_DATA_CONTENT_TYPE,
            plaintext = plaintext,
            key = secrets.serverWriteKey,
            iv = secrets.serverWriteIv,
            cipherSuite = secrets.cipherSuite,
            sequenceNumber = serverApplicationSequenceNumber,
            recordLengths = recordLengths,
        )
        serverApplicationSequenceNumber = checkedSequenceAfter(serverApplicationSequenceNumber, records.size)
        return records
    }

    private fun encryptProfiled(
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
