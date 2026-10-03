package org.givashot.tls.record

import org.givashot.tls.constant.TLS_MAX_RECORD_SIZE
import org.givashot.tls.constant.TLS_RECORD_HEADER_LENGTH

internal class TlsRecordDecoder(private val maxRecordSize: Int = TLS_MAX_RECORD_SIZE) {
    private val buffered = ByteQueue()

    init {
        require(maxRecordSize > TLS_RECORD_HEADER_LENGTH)
    }

    fun feed(bytes: ByteArray): List<TlsRecordMessage> {
        if (bytes.isEmpty()) return emptyList()
        buffered.append(bytes)
        val records = ArrayList<TlsRecordMessage>()
        while (buffered.size >= TLS_RECORD_HEADER_LENGTH) {
            val contentType = buffered[0].toInt() and 0xFF
            val version = ((buffered[1].toInt() and 0xFF) shl 8) or
                (buffered[2].toInt() and 0xFF)
            val payloadLength = ((buffered[3].toInt() and 0xFF) shl 8) or
                (buffered[4].toInt() and 0xFF)
            require(contentType in 20..23) { "Invalid TLS record content type: $contentType" }
            require(version ushr 8 == 3) { "Invalid TLS record legacy version: 0x${version.toString(16)}" }
            val recordLength = TLS_RECORD_HEADER_LENGTH + payloadLength
            require(recordLength <= maxRecordSize) { "TLS record exceeds maximum size limit" }
            if (buffered.size < recordLength) break

            val record = buffered.copyRange(0, recordLength)
            records += TlsRecordMessage(
                contentType = contentType,
                legacyRecordVersion = version,
                payload = record.copyOfRange(TLS_RECORD_HEADER_LENGTH, recordLength),
                encodedRecord = record,
            )
            buffered.discard(recordLength)
        }
        return records
    }

    fun reset() {
        buffered.clear()
    }
}
