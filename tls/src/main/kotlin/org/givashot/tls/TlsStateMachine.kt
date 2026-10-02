package org.givashot.tls

import org.bouncycastle.tls.ClientHello
import org.givashot.tls.constant.TLS_APPLICATION_DATA_CONTENT_TYPE
import org.givashot.tls.constant.TLS_HANDSHAKE_CLIENT_HELLO_CONTENT_TYPE
import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE
import org.givashot.tls.constant.TLS_HANDSHAKE_FINISH_CONTENT_TYPE
import org.givashot.tls.constant.TLS_HANDSHAKE_HEADER_LENGTH
import org.givashot.tls.constant.TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH
import org.givashot.tls.entity.ClientTlsEvent
import org.givashot.tls.entity.ApplicationSecrets
import org.givashot.tls.entity.handshake.CertificateData
import org.givashot.tls.entity.handshake.ClientHelloWrapper
import org.givashot.tls.entity.handshake.EncryptedExtensionsData
import org.givashot.tls.entity.handshake.HandshakeSecrets
import org.givashot.tls.entity.TlsRecordMessage
import java.util.ArrayDeque

enum class TlsPhase {
    EXPECT_CLIENT_HELLO,
    SERVER_FLIGHT_READY,
    EXPECT_CLIENT_FINISHED,
    APPLICATION_DATA,
    CLOSED,
}

class TlsStateMachine {
    private val recordDecoder = TlsRecordDecoder()
    private val serverHandshake = Tls13ServerHandshake()
    private val plaintextHandshakeDecoder = HandshakeMessageDecoder(TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH)
    private val encryptedHandshakeDecoder = HandshakeMessageDecoder()
    private val pendingRecords = ArrayDeque<TlsRecordMessage>()
    private var clientHello: ClientHelloWrapper? = null
    private var handshakeSecrets: HandshakeSecrets? = null
    private var applicationSecrets: ApplicationSecrets? = null
    private var transcript = ByteArray(0)
    private var transcriptHash: ByteArray? = null
    private val recordProtector = TlsRecordProtector()

    var phase: TlsPhase = TlsPhase.EXPECT_CLIENT_HELLO
        private set

    fun processClientData(bytes: ByteArray): List<ClientTlsEvent> {
        check(phase != TlsPhase.CLOSED) { "TLS connection is closed" }
        check(phase != TlsPhase.SERVER_FLIGHT_READY || bytes.isEmpty()) {
            "Server flight must be built before processing additional client data"
        }
        pendingRecords.addAll(recordDecoder.feed(bytes))
        val events = ArrayList<ClientTlsEvent>()
        while (pendingRecords.isNotEmpty() && phase != TlsPhase.SERVER_FLIGHT_READY) {
            val record = pendingRecords.removeFirst()
            when (phase) {
                TlsPhase.EXPECT_CLIENT_HELLO -> processClientHelloRecord(record.contentType, record.payload, events)
                TlsPhase.SERVER_FLIGHT_READY -> error("Unexpected TLS phase transition")
                TlsPhase.EXPECT_CLIENT_FINISHED -> processClientHandshakeRecord(
                    record.contentType,
                    record.encodedRecord,
                    events,
                )
                TlsPhase.APPLICATION_DATA -> processClientApplicationRecord(
                    record.contentType,
                    record.encodedRecord,
                    events,
                )
                TlsPhase.CLOSED -> error("TLS connection is closed")
            }
        }
        return events
    }

    fun close() {
        phase = TlsPhase.CLOSED
        pendingRecords.clear()
        recordDecoder.reset()
        plaintextHandshakeDecoder.reset()
        encryptedHandshakeDecoder.reset()
    }

    fun buildServerFlight(
        encryptedExtensions: EncryptedExtensionsData,
        certificate: CertificateData,
        recordLengths: List<Int>,
    ): List<ByteArray> {
        check(phase == TlsPhase.SERVER_FLIGHT_READY) { "Server flight is not valid in phase $phase" }
        require(certificate.certificateChain.isNotEmpty()) { "Server certificate chain is empty" }

        val result = serverHandshake.buildFlight(
            clientHello = checkNotNull(clientHello),
            transcript = transcript,
            encryptedExtensions = encryptedExtensions,
            certificate = certificate,
            recordLengths = recordLengths,
            recordProtector = recordProtector,
        )
        transcript = result.transcript
        transcriptHash = result.transcriptHash
        handshakeSecrets = result.handshakeSecrets
        applicationSecrets = result.applicationSecrets
        phase = TlsPhase.EXPECT_CLIENT_FINISHED
        return result.records
    }

    fun encryptServerApplicationData(
        plaintext: ByteArray,
        recordLengths: List<Int>,
    ): List<ByteArray> {
        check(phase == TlsPhase.APPLICATION_DATA) { "Application data is not valid in phase $phase" }
        val secrets = checkNotNull(applicationSecrets) { "Application secrets are unavailable" }
        return recordProtector.encryptApplicationData(plaintext, secrets, recordLengths)
    }

    private fun processClientHelloRecord(
        contentType: Int,
        payload: ByteArray,
        events: MutableList<ClientTlsEvent>,
    ) {
        require(contentType == TLS_HANDSHAKE_CONTENT_TYPE) { "Expected a ClientHello handshake record" }
        val messages = plaintextHandshakeDecoder.feed(payload)
        require(messages.size <= 1) { "Unexpected additional handshake message with ClientHello" }
        val message = messages.singleOrNull() ?: return
        require(plaintextHandshakeDecoder.bufferedByteCount == 0) {
            "ClientHello shares a record with additional handshake data"
        }
        require(message.type == TLS_HANDSHAKE_CLIENT_HELLO_CONTENT_TYPE) { "Expected ClientHello" }
        require(message.encodedBytes.size <= TLS_HANDSHAKE_MAX_CLIENT_HELLO_LENGTH) {
            "ClientHello exceeds configured size limit"
        }
        val wrapper = parseClientHello(message.encodedBytes)
        clientHello = wrapper
        transcript = message.encodedBytes
        phase = TlsPhase.SERVER_FLIGHT_READY
        events += ClientTlsEvent.ClientHello(wrapper)
    }

    private fun processClientHandshakeRecord(
        contentType: Int,
        encodedRecord: ByteArray,
        events: MutableList<ClientTlsEvent>,
    ) {
        require(contentType == TLS_APPLICATION_DATA_CONTENT_TYPE) {
            "Expected encrypted client handshake record"
        }
        val secrets = checkNotNull(handshakeSecrets) { "Handshake secrets are unavailable" }
        val plaintext = recordProtector.decryptHandshakeRecord(encodedRecord, secrets)
        val messages = encryptedHandshakeDecoder.feed(plaintext)
        require(messages.size <= 1) { "Unexpected additional handshake message with Client Finished" }
        val message = messages.singleOrNull() ?: return
        require(encryptedHandshakeDecoder.bufferedByteCount == 0) {
            "Client Finished shares a record with additional handshake data"
        }
        require(message.type == TLS_HANDSHAKE_FINISH_CONTENT_TYPE) { "Expected Client Finished" }
        val expectedHash = checkNotNull(transcriptHash) { "Server Finished transcript is unavailable" }
        check(verifyClientFinishedMessage(message.encodedBytes, secrets, expectedHash)) {
            "Client Finished verification failed"
        }

        transcript += message.encodedBytes
        transcriptHash = digest(transcript, secrets.cipherSuite)
        encryptedHandshakeDecoder.reset()
        phase = TlsPhase.APPLICATION_DATA
        events += ClientTlsEvent.ClientFinished
    }

    private fun processClientApplicationRecord(
        contentType: Int,
        encodedRecord: ByteArray,
        events: MutableList<ClientTlsEvent>,
    ) {
        require(contentType == TLS_APPLICATION_DATA_CONTENT_TYPE) { "Expected client application data record" }
        val secrets = checkNotNull(applicationSecrets) { "Application secrets are unavailable" }
        val plaintext = recordProtector.decryptApplicationRecord(encodedRecord, secrets)
        events += ClientTlsEvent.ClientApplicationData(plaintext)
    }

    private fun parseClientHello(encoded: ByteArray): ClientHelloWrapper {
        require(encoded.size >= TLS_HANDSHAKE_HEADER_LENGTH + 35) { "ClientHello is truncated" }
        val bodyOffset = TLS_HANDSHAKE_HEADER_LENGTH
        val sessionIdLengthOffset = TLS_HANDSHAKE_HEADER_LENGTH + 2 + 32
        val sessionIdLength = encoded[sessionIdLengthOffset].toInt() and 0xFF
        val sessionIdOffset = sessionIdLengthOffset + 1
        require(sessionIdOffset + sessionIdLength <= encoded.size) { "ClientHello session ID is truncated" }
        val parsed = ClientHello.parse(
            java.io.ByteArrayInputStream(encoded, bodyOffset, encoded.size - bodyOffset),
            null,
        )
        require(sessionIdLength == parsed.sessionID.size) { "ClientHello session ID length mismatch" }
        return ClientHelloWrapper(parsed, encoded, sessionIdOffset)
    }

}
