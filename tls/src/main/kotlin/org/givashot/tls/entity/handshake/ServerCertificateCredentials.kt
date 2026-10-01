package org.givashot.tls.entity.handshake

import java.security.PrivateKey

data class ServerCertificateCredentials(
    val certificateChain: List<ByteArray>,
    val privateKey: PrivateKey,
    val signatureScheme: Int,
    val jcaSignatureAlgorithm: String,
)