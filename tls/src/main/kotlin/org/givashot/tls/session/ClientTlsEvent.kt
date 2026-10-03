package org.givashot.tls.session

import org.givashot.tls.handshake.ClientHelloWrapper

sealed interface ClientTlsEvent {
    data class ClientHello(val hello: ClientHelloWrapper) : ClientTlsEvent
    data object ClientFinished : ClientTlsEvent
    data class ClientApplicationData(val data: ByteArray) : ClientTlsEvent
}
