package org.givashot.tls

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE
import org.givashot.tls.crypto.deriveX25519PublicKey
import org.givashot.tls.crypto.generateX25519PrivateKey
import org.givashot.tls.crypto.tlsRecord
import org.givashot.tls.session.ClientTlsEvent
import org.givashot.tls.handshake.CertificateData
import org.givashot.tls.handshake.EncryptedExtensionsData
import org.givashot.tls.session.TlsPhase
import org.givashot.tls.session.TlsResult
import org.givashot.tls.session.TlsServerStateMachine
import java.security.KeyPairGenerator

class TlsStateMachineTest {
    @Test
    fun `new state machine starts waiting for client hello`() {
        val machine = TlsServerStateMachine(ServerProfile(recordLengths = listOf(128)))
        assertEquals(TlsPhase.EXPECT_CLIENT_HELLO, machine.phase)
    }

    @Test
    fun `server flight cannot be built before client hello`() {
        val machine = TlsServerStateMachine(ServerProfile(recordLengths = listOf(128)))
        val privateKey = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair().private

        val result = machine.buildServerFlight(
            EncryptedExtensionsData(),
            CertificateData(emptyList(), privateKey, 0x0401, "SHA256withRSA"),
        )
        assertIs<TlsResult.Err>(result)
        assertEquals(TlsPhase.EXPECT_CLIENT_HELLO, machine.phase)
    }

    @Test
    fun `application data encryption is rejected before handshake completion`() {
        val machine = TlsServerStateMachine(ServerProfile(recordLengths = listOf(32)))
        val result = machine.encryptServerApplicationData(byteArrayOf(1))
        assertIs<TlsResult.Err>(result)
        assertEquals(TlsPhase.EXPECT_CLIENT_HELLO, machine.phase)
    }

    @Test
    fun `server flight creates hello and encrypted records from client hello`() {
        val clientPrivateKey = generateX25519PrivateKey()
        val clientHello = clientHelloRecord(clientPrivateKey.deriveX25519PublicKey())
        val machine = TlsServerStateMachine(ServerProfile(recordLengths = listOf(2048)))

        val eventsResult = machine.processClientData(clientHello)
        assertIs<TlsResult.Ok<List<ClientTlsEvent>>>(eventsResult)
        assertTrue(eventsResult.value.single() is ClientTlsEvent.ClientHello)
        assertEquals(TlsPhase.SERVER_FLIGHT_READY, machine.phase)

        val privateKey = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair().private
        val flight = machine.buildServerFlight(
            EncryptedExtensionsData(),
            CertificateData(listOf(byteArrayOf(1, 2, 3)), privateKey, 0x0401, "SHA256withRSA"),
        )

        assertIs<TlsResult.Ok<List<ByteArray>>>(flight)
        assertEquals(2, flight.value.size)
        assertEquals(TLS_HANDSHAKE_CONTENT_TYPE, flight.value[0][0].toInt() and 0xFF)
        assertEquals(TlsPhase.EXPECT_CLIENT_FINISHED, machine.phase)
        assertEquals(2048 + 5, flight.value[1].size)
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
