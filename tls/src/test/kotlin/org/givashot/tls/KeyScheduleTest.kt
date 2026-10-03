package org.givashot.tls

import org.givashot.tls.crypto.CipherSuite
import org.givashot.tls.crypto.Tls13KeySchedule
import org.givashot.tls.crypto.tlsHandshakeMessage
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class KeyScheduleTest {
    private val suites = listOf(
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
    ).map(CipherSuite::fromId)

    @Test
    fun `key schedule produces stable derived secrets`() {
        val sharedSecret = ByteArray(32) { index -> index.toByte() }

        for (suite in suites) {
            val transcript = ByteArray(suite.hashLength) { index -> (index * 3).toByte() }
            val schedule = Tls13KeySchedule(suite)
            schedule.deriveEarlySecret()
            schedule.deriveHandshakeSecret(sharedSecret)
            val handshake = schedule.handshakeSecrets(transcript)
            schedule.deriveMasterSecret()
            val application = schedule.applicationSecrets(transcript)

            assertEquals(suite.keyLen, handshake.serverWriteKey.size)
            assertEquals(suite.keyLen, handshake.clientWriteKey.size)
            assertEquals(suite.keyLen, application.serverWriteKey.size)
            assertEquals(suite.keyLen, application.clientWriteKey.size)

            val finished = schedule.finishedVerifyData(handshake.clientHandshakeTrafficSecret, transcript)
            val message = tlsHandshakeMessage(20, finished)
            assertTrue(schedule.verifyClientFinished(message, handshake.clientHandshakeTrafficSecret, transcript))
            assertContentEquals(
                finished,
                schedule.finishedVerifyData(handshake.clientHandshakeTrafficSecret, transcript),
            )
        }
    }

    @Test
    fun `second schedule with same inputs derives identical secrets`() {
        val suite = suites.first()
        val shared = ByteArray(32) { 7 }
        val hash = ByteArray(suite.hashLength) { 9 }
        fun derive() = Tls13KeySchedule(suite).also {
            it.deriveEarlySecret()
            it.deriveHandshakeSecret(shared)
        }.handshakeSecrets(hash)

        assertContentEquals(derive().serverHandshakeTrafficSecret, derive().serverHandshakeTrafficSecret)
    }

    @Test
    fun `finished verification rejects wrong data`() {
        val suite = suites.first()
        val transcript = ByteArray(suite.hashLength) { 1 }
        val schedule = Tls13KeySchedule(suite)
        schedule.deriveEarlySecret()
        schedule.deriveHandshakeSecret(ByteArray(32))
        val secrets = schedule.handshakeSecrets(transcript)
        val good = schedule.finishedVerifyData(secrets.clientHandshakeTrafficSecret, transcript)
        val bad = good.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }

        assertFalse(schedule.verifyClientFinished(tlsHandshakeMessage(20, bad), secrets.clientHandshakeTrafficSecret, transcript))
        assertFalse(schedule.verifyClientFinished(tlsHandshakeMessage(20, good.copyOf(good.size - 1)), secrets.clientHandshakeTrafficSecret, transcript))
    }

    @Test
    fun `stages must be derived in order`() {
        val schedule = Tls13KeySchedule(suites.first())
        assertFailsWith<IllegalStateException> { schedule.deriveHandshakeSecret(ByteArray(32)) }
        schedule.deriveEarlySecret()
        assertFailsWith<IllegalStateException> { schedule.deriveMasterSecret() }
    }
}
