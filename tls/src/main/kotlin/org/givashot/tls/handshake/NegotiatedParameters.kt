package org.givashot.tls.handshake

import org.bouncycastle.tls.NamedGroup
import org.bouncycastle.tls.ProtocolVersion
import org.givashot.tls.crypto.CipherSuite

internal data class NegotiatedParameters(
    val cipherSuite: CipherSuite,
    val version: ProtocolVersion = ProtocolVersion.TLSv13,
    val namedGroup: Int = NamedGroup.x25519,
)
