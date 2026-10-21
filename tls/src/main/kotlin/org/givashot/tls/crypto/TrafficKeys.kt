package org.givashot.tls.crypto

/** One generation of traffic keys for one direction. Immutable; the record sequence number lives in the record layer. */
internal class TrafficKeys(
    val key: ByteArray,
    val iv: ByteArray,
    val cipherSuite: CipherSuite,
    val trafficSecret: ByteArray,
)
