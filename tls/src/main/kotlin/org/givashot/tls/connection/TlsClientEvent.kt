package org.givashot.tls.connection

import org.givashot.tls.handshake.ClientHelloWrapper

sealed interface TlsClientEvent {
    data class ClientHello(val hello: ClientHelloWrapper) : TlsClientEvent
    data object ClientFinished : TlsClientEvent
    data class ClientApplicationData(val data: ByteArray) : TlsClientEvent
    data class ClientAlert(val alertCode: Int, val reply: ByteArray? = null) : TlsClientEvent
    data class ClientKeyUpdate(val reply: ByteArray? = null) : TlsClientEvent

    /** Protocol errors may still carry a fatal alert that must be written before closing the transport. */
    data class ClientError(
        val peerProtocolException: TlsPeerProtocolException,
        val reply: ByteArray,
    ) : TlsClientEvent
}
