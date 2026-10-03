package org.givashot.tls.session

import org.givashot.tls.crypto.ApplicationSecrets
import org.givashot.tls.crypto.HandshakeSecrets
import org.givashot.tls.handshake.ClientHelloWrapper
import org.givashot.tls.handshake.HandshakeMessageDecoder

enum class TlsPhase {
    EXPECT_CLIENT_HELLO,
    SERVER_FLIGHT_READY,
    EXPECT_CLIENT_FINISHED,
    APPLICATION_DATA,
    FAILED,
    CLOSED,
}

internal sealed interface TlsState {
    val phase: TlsPhase

    class AwaitClientHello(val handshakeDecoder: HandshakeMessageDecoder) : TlsState {
        override val phase: TlsPhase = TlsPhase.EXPECT_CLIENT_HELLO
    }

    class AwaitServerFlight(val clientHello: ClientHelloWrapper) : TlsState {
        override val phase: TlsPhase = TlsPhase.SERVER_FLIGHT_READY
    }

    class AwaitClientFinished(
        val handshakeSecrets: HandshakeSecrets,
        val applicationSecrets: ApplicationSecrets,
        val transcriptHash: ByteArray,
        val handshakeDecoder: HandshakeMessageDecoder = HandshakeMessageDecoder(),
    ) : TlsState {
        override val phase: TlsPhase = TlsPhase.EXPECT_CLIENT_FINISHED
    }

    data object Established : TlsState {
        override val phase: TlsPhase = TlsPhase.APPLICATION_DATA
    }

    class Failed(val error: TlsError.Peer) : TlsState {
        override val phase: TlsPhase = TlsPhase.FAILED
    }

    data object Closed : TlsState {
        override val phase: TlsPhase = TlsPhase.CLOSED
    }
}
