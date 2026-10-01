package org.givashot.tls

import org.givashot.tls.constant.*
import org.givashot.tls.entity.handshake.CipherSuite
import org.givashot.tls.entity.handshake.HandshakeSecrets
import org.givashot.tls.entity.handshake.ServerCertificateCredentials
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
    return tlsHandshakeMessage(TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS_CONTENT_TYPE, body.toByteArray())
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
    return tlsHandshakeMessage(TLS_HANDSHAKE_CERTIFICATE_CONTENT_TYPE, body.toByteArray())
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
    return tlsHandshakeMessage(TLS_HANDSHAKE_CERTIFICATE_VERIFY_CONTENT_TYPE, body.toByteArray())
}

/**
 * Encrypt server flight according to the observed TLS record profile.
 *
 * The handshake messages are split as one continuous byte stream. A handshake
 * message may therefore span multiple records, while padding is kept outside
 * the transcript by the TLS record layer.
 */
fun encryptServerFlight(
    encryptedExtensions: ByteArray,
    certificate: ByteArray,
    certificateVerify: ByteArray,
    finished: ByteArray,
    secrets: HandshakeSecrets,
    recordLengths: List<Int>,
    sequenceNumber: Long = 0,
): List<ByteArray> {
    val flight = encryptedExtensions + certificate + certificateVerify + finished
    require(recordLengths.isNotEmpty()) { "TLS handshake record profile is empty" }

    var offset = 0
    return recordLengths.mapIndexed { index, targetLength ->
        val minPayloadLength = 1 + TLS_AEAD_TAG_LENGTH
        require(targetLength in minPayloadLength..TLS_MAX_RECORD_SIZE - TLS_RECORD_HEADER_LENGTH) {
            "Invalid TLS handshake record length: $targetLength"
        }
        require(sequenceNumber <= Long.MAX_VALUE - index) {
            "TLS handshake sequence number overflow"
        }

        val plaintextCapacity = targetLength - minPayloadLength
        val plaintextLength = minOf(plaintextCapacity, flight.size - offset)
        val paddingLength = plaintextCapacity - plaintextLength
        val plaintext = flight.copyOfRange(offset, offset + plaintextLength)
        offset += plaintextLength

        encryptTlsRecord(
            contentType = TLS_HANDSHAKE_CONTENT_TYPE,
            plaintext = plaintext,
            writeKey = secrets.serverWriteKey,
            writeIv = secrets.serverWriteIv,
            sequenceNumber = sequenceNumber + index,
            cipherSuite = secrets.cipherSuite,
            paddingLength = paddingLength,
        )
    }.also {
        require(offset == flight.size) {
            "TLS handshake record profile cannot contain the server flight"
        }
    }
}

fun buildFinishedMessage(
    trafficSecret: ByteArray,
    transcriptHash: ByteArray,
    cipherSuite: CipherSuite,
): ByteArray {
    val finishedKey = hkdfExpandLabel(
        trafficSecret,
        "finished",
        ByteArray(0),
        cipherSuite.hashLength,
        cipherSuite,
    )
    return tlsHandshakeMessage(
        type = TLS_HANDSHAKE_FINISH_CONTENT_TYPE,
        body = hmac(finishedKey, transcriptHash, cipherSuite),
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