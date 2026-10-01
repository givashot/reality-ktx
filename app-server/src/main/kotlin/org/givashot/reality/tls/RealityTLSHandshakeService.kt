package org.givashot.reality.tls

import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.util.AttributeKey
import org.givashot.tls.*
import org.givashot.tls.constant.TLS_HANDSHAKE_CONTENT_TYPE
import org.givashot.tls.entity.handshake.ClientHelloWrapper
import java.util.logging.Level
import java.util.logging.Logger

class RealityTLSHandshakeService(
    private val handshakeRecordProfile: HandshakeRecordProfile
) : TlsHandshakeService {

    override fun complete(
        channel: Channel,
        clientHelloWrapper: ClientHelloWrapper,
        authKey: ByteArray
    ) {
        val credentials = applyAuthKeySignature(
            authKey = authKey,
        )
        val serverHello = newServerHello(clientHelloWrapper)
        val serverHelloHandshake = serverHello.base.encodeHandshake()
        val handshakeSecrets = deriveHandshakeSecrets(
            clientHello = clientHelloWrapper,
            serverHello = serverHello,
            sharedSecret = serverHello.sharedSecret,
            cipherSuite = serverHello.cipherSuite,
        )
        val state = TlsConnectionState(clientHelloWrapper, serverHello, handshakeSecrets, serverHelloHandshake)
        val serverHelloRecord = tlsRecord(TLS_HANDSHAKE_CONTENT_TYPE, serverHelloHandshake)

        val encryptedExtensions = encodeEncryptedExtensions(emptyMap())
        val certificate = encodeCertificate(credentials)
        val transcriptAfterCertificate = tlsTranscriptHash(
            serverHello.cipherSuite,
            clientHelloWrapper.handshakeAndBody,
            serverHelloHandshake,
            encryptedExtensions,
            certificate,
        )
        val certificateVerify = encodeCertificateVerify(credentials, transcriptAfterCertificate)
        val transcriptAfterCertificateVery = tlsTranscriptHash(
            serverHello.cipherSuite,
            clientHelloWrapper.handshakeAndBody,
            serverHelloHandshake,
            encryptedExtensions,
            certificate,
            certificateVerify,
        )
        val finished = buildFinishedMessage(
            handshakeSecrets.serverHandshakeTrafficSecret,
            transcriptAfterCertificateVery,
            serverHello.cipherSuite,
        )
        val transcriptAfterFinished = tlsTranscriptHash(
            serverHello.cipherSuite,
            clientHelloWrapper.handshakeAndBody,
            serverHelloHandshake,
            encryptedExtensions,
            certificate,
            certificateVerify,
            finished,
        )
        val serverFlightSequenceNumber = state.serverHandshakeSequenceNumber
        val encryptedServerFlight = runCatching {
            encryptServerFlight(
                encryptedExtensions,
                certificate,
                certificateVerify,
                finished,
                handshakeSecrets,
                handshakeRecordProfile.recordLengths,
                serverFlightSequenceNumber,
            )
        }.getOrElse {
            logger.log(Level.WARNING, "Closing connection: fallback record profile cannot contain server flight", it)
            channel.close()
            return
        }
        state.transcript += encryptedExtensions + certificate + certificateVerify + finished
        state.serverFlightTranscriptHash = transcriptAfterFinished
        state.phase = TlsHandshakePhase.SERVER_FLIGHT_SENT
        state.serverHandshakeSequenceNumber += encryptedServerFlight.size
        channel.attr(TLS_STATE_KEY).set(state)
        channel.writeAndFlush(
            Unpooled.wrappedBuffer(
                serverHelloRecord,
                *encryptedServerFlight.toTypedArray()
            )
        )
    }

    companion object {
        private val logger = Logger.getLogger(RealityTLSHandshakeService::class.java.name)
        val TLS_STATE_KEY: AttributeKey<TlsConnectionState> =
            AttributeKey.valueOf("reality.tls.state")
    }
}
