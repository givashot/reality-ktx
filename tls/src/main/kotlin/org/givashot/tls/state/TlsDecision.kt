package org.givashot.tls.state

import org.givashot.tls.connection.TlsPeerProtocolException

sealed interface TlsDecision {
    data object Ignore : TlsDecision
    object HandshakeFragment : TlsDecision
    object ApplicationData : TlsDecision
    object ClientAlert : TlsDecision
    data class Reject(val exception: TlsPeerProtocolException) : TlsDecision
}