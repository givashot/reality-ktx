package org.givashot.tls.entity

internal data class TlsRecordMessage(
    val contentType: Int,
    val legacyRecordVersion: Int,
    val payload: ByteArray,
    val encodedRecord: ByteArray,
)
