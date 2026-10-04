package org.givashot.tls

import org.givashot.tls.constant.TLS_APPLICATION_DATA_CONTENT_TYPE
import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE
import org.givashot.tls.crypto.CipherSuite
import org.givashot.tls.crypto.HandshakeTrafficSecrets
import org.givashot.tls.crypto.Tls13KeySchedule
import org.givashot.tls.crypto.TrafficKeys
import org.givashot.tls.crypto.calcSharedSecret
import org.givashot.tls.crypto.decryptTlsRecord
import org.givashot.tls.crypto.deriveX25519PublicKey
import org.givashot.tls.crypto.digest
import org.givashot.tls.crypto.encryptTlsRecord
import org.givashot.tls.crypto.generateX25519PrivateKey
import org.givashot.tls.crypto.tlsHandshakeMessage
import org.givashot.tls.crypto.tlsRecord
import org.givashot.tls.handshake.CertificateData
import java.security.KeyPairGenerator

/** Minimal TLS 1.3 client used to drive a server-side TlsConnection end to end in tests. */
internal class TestTlsClient(cipherSuiteId: Int = 0x1301) {
    private val privateKey = generateX25519PrivateKey()
    val publicKey: ByteArray = privateKey.deriveX25519PublicKey()
    val clientHelloHandshake: ByteArray = buildClientHello(publicKey, cipherSuiteId)
    val clientHelloRecord: ByteArray = tlsRecord(TLS_HANDSHAKE_CONTENT_TYPE, clientHelloHandshake)

    lateinit var suite: CipherSuite
    lateinit var handshakeTrafficSecrets: HandshakeTrafficSecrets
    lateinit var serverFlightHandshake: ByteArray
    private lateinit var schedule: Tls13KeySchedule
    private lateinit var serverHelloHandshake: ByteArray
    private lateinit var writeKeys: TrafficKeys
    private var readKeys: TrafficKeys? = null

    /** Consumes ServerHello plus encrypted flight records; returns the decrypted encrypted-handshake bytes. */
    fun processServerFlight(records: List<ByteArray>): ByteArray {
        serverHelloHandshake = records.first().copyOfRange(5, records.first().size)
        val sessionIdLength = serverHelloHandshake[4 + 2 + 32].toInt() and 0xFF
        val suiteOffset = 4 + 2 + 32 + 1 + sessionIdLength
        suite = CipherSuite.fromId(
            ((serverHelloHandshake[suiteOffset].toInt() and 0xFF) shl 8) or
                (serverHelloHandshake[suiteOffset + 1].toInt() and 0xFF),
        )
        val serverPublicKey = findServerKeyShare(serverHelloHandshake)
        schedule = Tls13KeySchedule(suite)
        schedule.deriveEarlySecret()
        schedule.deriveHandshakeSecret(calcSharedSecret(privateKey, serverPublicKey))
        handshakeTrafficSecrets = schedule.handshakeTrafficSecrets(digest(clientHelloHandshake + serverHelloHandshake, suite))

        val serverKeys = handshakeTrafficSecrets.serverTrafficKeys()
        writeKeys = handshakeTrafficSecrets.clientTrafficKeys()
        val out = java.io.ByteArrayOutputStream()
        for (record in records.drop(1)) {
            val decrypted = decryptTlsRecord(record, serverKeys.key, serverKeys.iv, serverKeys.sequenceNumber++, suite)
            check(decrypted.contentType == TLS_HANDSHAKE_CONTENT_TYPE)
            out.write(decrypted.payload)
        }
        serverFlightHandshake = out.toByteArray()
        return serverFlightHandshake
    }

    fun transcriptThroughServerFinished(): ByteArray =
        clientHelloHandshake + serverHelloHandshake + serverFlightHandshake

    fun finishedRecord(): ByteArray {
        val hash = digest(transcriptThroughServerFinished(), suite)
        val verifyData = schedule.finishedVerifyData(handshakeTrafficSecrets.clientHandshakeTrafficSecret, hash)
        return encryptHandshake(tlsHandshakeMessage(20, verifyData))
    }

    fun encryptHandshake(message: ByteArray): ByteArray = encryptTlsRecord(
        TLS_HANDSHAKE_CONTENT_TYPE, message, writeKeys.key, writeKeys.iv, writeKeys.sequenceNumber++, suite,
    )

    /** Switches to application keys; call after the client Finished has been sent. */
    fun startApplicationPhase() {
        schedule.deriveMasterSecret()
        val application = schedule.applicationTrafficSecrets(digest(transcriptThroughServerFinished(), suite))
        writeKeys = application.clientTrafficKeys()
        readKeys = application.serverTrafficKeys()
    }

    fun encryptApplicationData(data: ByteArray): ByteArray = encryptTlsRecord(
        TLS_APPLICATION_DATA_CONTENT_TYPE, data, writeKeys.key, writeKeys.iv, writeKeys.sequenceNumber++, suite,
    )

    fun decryptApplicationData(record: ByteArray): ByteArray {
        val keys = checkNotNull(readKeys)
        val decrypted = decryptTlsRecord(record, keys.key, keys.iv, keys.sequenceNumber++, suite)
        check(decrypted.contentType == TLS_APPLICATION_DATA_CONTENT_TYPE)
        return decrypted.payload
    }

    companion object {
        val ccsRecord: ByteArray = byteArrayOf(0x14, 3, 3, 0, 1, 1)

        fun certificate(): CertificateData {
            val privateKey = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair().private
            return CertificateData(listOf(byteArrayOf(1, 2, 3)), privateKey, 0x0401, "SHA256withRSA")
        }

        fun buildClientHello(clientPublicKey: ByteArray, cipherSuiteId: Int = 0x1301): ByteArray {
            val keyShare = byteArrayOf(0, 36, 0, 29, 0, 32) + clientPublicKey
            val keyShareExtension = byteArrayOf(0, 51, 0, 38) + keyShare
            val extensions = byteArrayOf(0, keyShareExtension.size.toByte()) + keyShareExtension
            val body = byteArrayOf(3, 3) +
                ByteArray(32) +
                byteArrayOf(0, 0, 2, (cipherSuiteId ushr 8).toByte(), cipherSuiteId.toByte(), 1, 0) +
                extensions
            return byteArrayOf(1, (body.size ushr 16).toByte(), (body.size ushr 8).toByte(), body.size.toByte()) + body
        }

        private fun findServerKeyShare(serverHello: ByteArray): ByteArray {
            val marker = byteArrayOf(0, 51, 0, 36, 0, 29, 0, 32)
            for (i in 0..serverHello.size - marker.size - 32) {
                if (marker.indices.all { serverHello[i + it] == marker[it] }) {
                    return serverHello.copyOfRange(i + marker.size, i + marker.size + 32)
                }
            }
            error("ServerHello has no x25519 key share")
        }
    }
}
