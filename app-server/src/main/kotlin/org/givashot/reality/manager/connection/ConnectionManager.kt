package org.givashot.reality.manager.connection

import io.netty.channel.Channel
import org.givashot.reality.authentication.AuthResult
import org.givashot.reality.tls.TlsHandshakeService
import org.givashot.tls.ClientHelloWrapper

class ConnectionManager(
    private val tlsHandshakeService: TlsHandshakeService,
) {

    fun onAuthenticated(channel: Channel, clientHelloWrapper: ClientHelloWrapper, result: AuthResult.Success) {
        tlsHandshakeService.complete(channel, clientHelloWrapper, result.authKey)
    }

}
