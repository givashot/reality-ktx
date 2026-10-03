package org.givashot.tls.connection

import org.givashot.tls.handshake.ClientHelloWrapper

sealed interface TlsEvent {
    data class ClientHello(val hello: ClientHelloWrapper) : TlsEvent
    data object ClientFinished : TlsEvent
    data class ClientApplicationData(val data: ByteArray) : TlsEvent
}
