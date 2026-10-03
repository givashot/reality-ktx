package org.givashot.tls.connection

import org.givashot.tls.handshake.CertificateData
import org.givashot.tls.handshake.EncryptedExtensionsData

sealed interface TlsCommand {
    /** Complete the handshake with ServerHello and the encrypted server flight. Null recordLengths means the profile default. */
    data class SendServerFlight(
        val encryptedExtensions: EncryptedExtensionsData,
        val certificate: CertificateData,
        val recordLengths: List<Int>? = null,
    ) : TlsCommand

    data class SendApplicationData(
        val data: ByteArray,
        val recordLengths: List<Int>? = null,
    ) : TlsCommand

    data object Close : TlsCommand
}
