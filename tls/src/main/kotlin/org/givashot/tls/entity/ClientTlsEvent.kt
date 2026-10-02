package org.givashot.tls.entity

import org.givashot.tls.entity.handshake.ClientHelloWrapper

sealed interface ClientTlsEvent {
    data class ClientHello(val hello: ClientHelloWrapper) : ClientTlsEvent
    data object ClientFinished : ClientTlsEvent
    data class ClientApplicationData(val data: ByteArray) : ClientTlsEvent
}
