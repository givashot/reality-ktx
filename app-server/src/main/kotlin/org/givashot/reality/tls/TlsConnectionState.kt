package org.givashot.reality.tls

import org.givashot.tls.ApplicationSecrets
import org.givashot.tls.ClientHelloWrapper
import org.givashot.tls.HandshakeSecrets
import org.givashot.tls.ServerHelloWrapper

enum class TlsHandshakePhase {
    SERVER_HELLO_SENT,
    SERVER_FLIGHT_SENT,
    APPLICATION_DATA,
    CLOSED,
}

class TlsConnectionState(
    val clientHello: ClientHelloWrapper,
    val serverHello: ServerHelloWrapper,
    val handshakeSecrets: HandshakeSecrets,
    val serverHelloHandshake: ByteArray,
) {
    var transcript: ByteArray = clientHello.handshakeAndBody + serverHelloHandshake
    var phase: TlsHandshakePhase = TlsHandshakePhase.SERVER_HELLO_SENT
    var serverHandshakeSequenceNumber: Long = 0
    var clientHandshakeSequenceNumber: Long = 0
    var serverFlightTranscriptHash: ByteArray? = null
    var serverApplicationSequenceNumber: Long = 0
    var clientApplicationSequenceNumber: Long = 0
    var applicationSecrets: ApplicationSecrets? = null
}
