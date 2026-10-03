package org.givashot.tls

import org.givashot.tls.crypto.KeySchedule
import org.givashot.tls.crypto.tlsHandshakeMessage
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.givashot.tls.handshake.CipherSuite

class KeyScheduleTest {
    @Test
    fun `key schedule produces stable derived secrets`() {
        val sharedSecret = ByteArray(32) { index -> index.toByte() }

        for (suiteId in listOf(
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        )) {
            val suite = CipherSuite.fromId(suiteId)
            val transcript = ByteArray(suite.hashLength) { index -> (index * 3).toByte() }
            val handshake = KeySchedule.deriveHandshakeSecrets(sharedSecret, transcript, suite)
            val application = KeySchedule.deriveApplicationSecrets(handshake, transcript)

            assertEquals(suite.keyLen, handshake.serverWriteKey.size)
            assertEquals(suite.keyLen, handshake.clientWriteKey.size)
            assertEquals(suite.keyLen, application.serverWriteKey.size)
            assertEquals(suite.keyLen, application.clientWriteKey.size)

            val finished = KeySchedule.finishedVerifyData(
                handshake.clientHandshakeTrafficSecret,
                transcript,
                suite,
            )
            val message = tlsHandshakeMessage(20, finished)
            assertTrue(KeySchedule.verifyClientFinished(message, handshake, transcript))
            assertContentEquals(finished, KeySchedule.finishedVerifyData(
                handshake.clientHandshakeTrafficSecret,
                transcript,
                suite,
            ))
        }
    }
}
