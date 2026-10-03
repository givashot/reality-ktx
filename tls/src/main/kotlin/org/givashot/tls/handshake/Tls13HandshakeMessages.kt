package org.givashot.tls.handshake

import org.givashot.tls.crypto.KeySchedule
import org.givashot.tls.constant.*
import org.givashot.tls.crypto.tlsHandshakeMessage
import java.io.ByteArrayOutputStream
import java.security.Signature

internal fun encodeEncryptedExtensions(extensions: Map<Int, ByteArray>): ByteArray {
    val extensionBytes = ByteArrayOutputStream()
    extensions.forEach { (type, data) ->
        require(type in 0..0xFFFF && data.size <= 0xFFFF)
        writeUint16(type, extensionBytes)
        writeUint16(data.size, extensionBytes)
        extensionBytes.write(data)
    }
    require(extensionBytes.size() <= 0xFFFF) { "EncryptedExtensions is too large" }
    val body = ByteArrayOutputStream()
    writeUint16(extensionBytes.size(), body)
    body.write(extensionBytes.toByteArray())
    return tlsHandshakeMessage(TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS_CONTENT_TYPE, body.toByteArray())
}

internal fun encodeCertificate(certificateData: CertificateData): ByteArray {
    require(certificateData.certificateChain.isNotEmpty())
    val certificateList = ByteArrayOutputStream()
    certificateData.certificateChain.forEach { certificate ->
        require(certificate.size <= 0xFFFFFF)
        writeUint24(certificate.size, certificateList)
        certificateList.write(certificate)
        writeUint16(0, certificateList)
    }
    require(certificateList.size() <= 0xFFFFFF) { "Certificate list is too large" }
    val body = ByteArrayOutputStream()
    body.write(0)
    writeUint24(certificateList.size(), body)
    body.write(certificateList.toByteArray())
    return tlsHandshakeMessage(TLS_HANDSHAKE_CERTIFICATE_CONTENT_TYPE, body.toByteArray())
}

internal fun encodeCertificateVerify(
    certificate: CertificateData,
    transcriptHash: ByteArray,
): ByteArray {
    val signatureInput = ByteArray(64) { 0x20 } +
            "TLS 1.3, server CertificateVerify".toByteArray(Charsets.US_ASCII) +
            byteArrayOf(0) + transcriptHash
    val signer = Signature.getInstance(certificate.jcaSignatureAlgorithm)
    signer.initSign(certificate.privateKey)
    signer.update(signatureInput)
    val signature = signer.sign()
    val body = ByteArrayOutputStream()
    writeUint16(certificate.signatureScheme, body)
    require(signature.size <= 0xFFFF)
    writeUint16(signature.size, body)
    body.write(signature)
    return tlsHandshakeMessage(TLS_HANDSHAKE_CERTIFICATE_VERIFY_CONTENT_TYPE, body.toByteArray())
}

internal fun buildFinishedMessage(
    trafficSecret: ByteArray,
    transcriptHash: ByteArray,
    cipherSuite: CipherSuite,
): ByteArray {
    return tlsHandshakeMessage(
        type = TLS_HANDSHAKE_FINISH_CONTENT_TYPE,
        body = KeySchedule.finishedVerifyData(trafficSecret, transcriptHash, cipherSuite),
    )
}

private fun writeUint16(value: Int, output: ByteArrayOutputStream) {
    output.write((value ushr 8) and 0xFF)
    output.write(value and 0xFF)
}

private fun writeUint24(value: Int, output: ByteArrayOutputStream) {
    output.write((value ushr 16) and 0xFF)
    output.write((value ushr 8) and 0xFF)
    output.write(value and 0xFF)
}
