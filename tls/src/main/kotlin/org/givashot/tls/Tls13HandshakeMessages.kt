package org.givashot.tls

import java.io.ByteArrayOutputStream
import java.security.Signature


fun encodeEncryptedExtensions(extensions: Map<Int, ByteArray>): ByteArray {
    val extensionBytes = ByteArrayOutputStream()
    extensions.forEach { (type, data) ->
        require(type in 0..0xFFFF && data.size <= 0xFFFF)
        writeUint16(type, extensionBytes)
        writeUint16(data.size, extensionBytes)
        extensionBytes.write(data)
    }
    val body = ByteArrayOutputStream()
    writeUint16(extensionBytes.size(), body)
    body.write(extensionBytes.toByteArray())
    return tlsHandshakeMessage(8, body.toByteArray())
}

fun encodeCertificate(credentials: ServerCertificateCredentials): ByteArray {
    require(credentials.certificateChain.isNotEmpty())
    val certificateList = ByteArrayOutputStream()
    credentials.certificateChain.forEach { certificate ->
        require(certificate.size <= 0xFFFFFF)
        writeUint24(certificate.size, certificateList)
        certificateList.write(certificate)
        writeUint16(0, certificateList)
    }
    val body = ByteArrayOutputStream()
    body.write(0)
    writeUint24(certificateList.size(), body)
    body.write(certificateList.toByteArray())
    return tlsHandshakeMessage(11, body.toByteArray())
}

fun encodeCertificateVerify(
    credentials: ServerCertificateCredentials,
    transcriptHash: ByteArray,
): ByteArray {
    val signatureInput = ByteArray(64) { 0x20 } +
            "TLS 1.3, server CertificateVerify".toByteArray(Charsets.US_ASCII) +
            byteArrayOf(0) + transcriptHash
    val signer = Signature.getInstance(credentials.jcaSignatureAlgorithm)
    signer.initSign(credentials.privateKey)
    signer.update(signatureInput)
    val signature = signer.sign()
    val body = ByteArrayOutputStream()
    writeUint16(credentials.signatureScheme, body)
    require(signature.size <= 0xFFFF)
    writeUint16(signature.size, body)
    body.write(signature)
    return tlsHandshakeMessage(15, body.toByteArray())
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