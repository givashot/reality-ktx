package org.givashot.tls.handshake

import org.givashot.tls.crypto.CipherSuite
import org.givashot.tls.crypto.digest
import java.io.ByteArrayOutputStream

/** Accumulates handshake messages; the hash algorithm is only known after cipher suite negotiation. */
internal class TranscriptHash {
    private val messages = ByteArrayOutputStream()

    fun update(message: ByteArray) {
        messages.write(message)
    }

    fun hash(cipherSuite: CipherSuite): ByteArray = digest(messages.toByteArray(), cipherSuite)
}
