package org.givashot.tls.handshake

import org.givashot.tls.crypto.CipherSuite
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/** Accumulates handshake messages; the hash algorithm is only known after cipher suite negotiation. */
internal class TranscriptHash {
    private val messages = ByteArrayOutputStream()

    fun update(message: ByteArray) {
        messages.write(message)
    }

    fun hash(cipherSuite: CipherSuite): ByteArray =
        MessageDigest.getInstance(cipherSuite.hash).digest(messages.toByteArray())

}
