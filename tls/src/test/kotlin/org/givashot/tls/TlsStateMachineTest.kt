package org.givashot.tls

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE
import org.givashot.tls.entity.handshake.CertificateData
import org.givashot.tls.entity.handshake.EncryptedExtensionsData
import org.givashot.tls.entity.ClientTlsEvent
import java.security.KeyPairGenerator

class TlsStateMachineTest {
    @Test
    fun `new state machine starts waiting for client hello`() {
        assertEquals(TlsPhase.EXPECT_CLIENT_HELLO, TlsStateMachine().phase)
    }

    @Test
    fun `server flight cannot be built before client hello`() {
        val machine = TlsStateMachine()
        val privateKey = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair().private

        assertFailsWith<IllegalStateException> {
            machine.buildServerFlight(
                EncryptedExtensionsData(),
                CertificateData(emptyList(), privateKey, 0x0401, "SHA256withRSA"),
                listOf(128),
            )
        }
        assertEquals(TlsPhase.EXPECT_CLIENT_HELLO, machine.phase)
    }

    @Test
    fun `application data encryption is rejected before handshake completion`() {
        val machine = TlsStateMachine()
        assertFailsWith<IllegalStateException> {
            machine.encryptServerApplicationData(byteArrayOf(1), listOf(32))
        }
        assertEquals(TlsPhase.EXPECT_CLIENT_HELLO, machine.phase)
    }

    @Test
    fun `server flight creates hello and encrypted records from client hello`() {
        val clientPrivateKey = generateX25519PrivateKey()
        val clientHello = clientHelloRecord(clientPrivateKey.deriveX25519PublicKey())
        val machine = TlsStateMachine()

        val events = machine.processClientData(clientHello)
        assertTrue(events.single() is ClientTlsEvent.ClientHello)
        assertEquals(TlsPhase.SERVER_FLIGHT_READY, machine.phase)

        val privateKey = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair().private
        val flight = machine.buildServerFlight(
            EncryptedExtensionsData(),
            CertificateData(listOf(byteArrayOf(1, 2, 3)), privateKey, 0x0401, "SHA256withRSA"),
            listOf(2048),
        )

        assertEquals(2, flight.size)
        assertEquals(TLS_HANDSHAKE_CONTENT_TYPE, flight[0][0].toInt() and 0xFF)
        assertEquals(TlsPhase.EXPECT_CLIENT_FINISHED, machine.phase)
        assertEquals(2048 + 5, flight[1].size)
        assertFailsWith<IllegalStateException> {
            machine.buildServerFlight(
                EncryptedExtensionsData(),
                CertificateData(listOf(byteArrayOf(1)), privateKey, 0x0401, "SHA256withRSA"),
                listOf(2048),
            )
        }
    }

    private fun clientHelloRecord(clientPublicKey: ByteArray): ByteArray {
        val keyShare = byteArrayOf(0, 36, 0, 29, 0, 32) + clientPublicKey
        val keyShareExtension = byteArrayOf(0, 51, 0, 38) + keyShare
        val extensions = byteArrayOf(0, keyShareExtension.size.toByte()) + keyShareExtension
        val body = byteArrayOf(3, 3) +
            ByteArray(32) +
            byteArrayOf(0, 0, 2, 19, 1, 1, 0) +
            extensions
        val handshake = byteArrayOf(
            1,
            (body.size ushr 16).toByte(),
            (body.size ushr 8).toByte(),
            body.size.toByte(),
        ) + body
        return tlsRecord(TLS_HANDSHAKE_CONTENT_TYPE, handshake)
    }
}
