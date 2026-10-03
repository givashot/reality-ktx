package org.givashot.tls.crypto

internal class TrafficKeys(
    val key: ByteArray,
    val iv: ByteArray,
    val cipherSuite: CipherSuite,
    var sequenceNumber: Long = 0L,
)
