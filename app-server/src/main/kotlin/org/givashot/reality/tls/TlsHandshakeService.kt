package org.givashot.reality.tls

import io.netty.channel.Channel
import org.givashot.tls.entity.ClientHelloWrapper

fun interface TlsHandshakeService {

    fun complete(channel: Channel, clientHelloWrapper: ClientHelloWrapper, authKey: ByteArray)

}