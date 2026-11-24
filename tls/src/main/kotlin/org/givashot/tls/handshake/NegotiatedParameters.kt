package org.givashot.tls.handshake

import org.givashot.tls.constant.TLS_NAMED_GROUP_X25519
import org.givashot.tls.constant.TLS_VERSION_1_3
import org.givashot.tls.crypto.CipherSuite

internal data class NegotiatedParameters(
    val cipherSuite: CipherSuite,
    val version: Int = TLS_VERSION_1_3,
    val namedGroup: Int = TLS_NAMED_GROUP_X25519,
)
