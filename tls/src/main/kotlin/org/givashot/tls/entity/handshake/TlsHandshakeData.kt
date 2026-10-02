package org.givashot.tls.entity.handshake

import java.security.PrivateKey

data class EncryptedExtensionsData(
    val extensions: Map<Int, ByteArray> = emptyMap(),
)

data class CertificateData(
    val certificateChain: List<ByteArray>,
    val privateKey: PrivateKey,
    val signatureScheme: Int,
    val jcaSignatureAlgorithm: String,
)

