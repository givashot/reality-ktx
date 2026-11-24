package org.givashot.reality.crypto

import org.givashot.tls.crypto.globalSecureRandom
import org.givashot.tls.handshake.CertificateData
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// TLS 1.3 SignatureScheme.ed25519 = 0x0807
private const val SIGNATURE_SCHEME_ED25519 = 0x0807
private const val JCA_SIG_ALG_ED25519 = "Ed25519"

private const val ED25519_KEY_SIZE_BYTES = 32
private const val ED25519_SIGNATURE_SIZE_BYTES = 64

// AlgorithmIdentifier: SEQUENCE { OID 1.3.101.112 (Ed25519) }
private val ED25519_ALG_ID = byteArrayOf(0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70)

// Name: SEQUENCE { SET { SEQUENCE { OID 2.5.4.3 (CN), UTF8String "" } } }
private val EMPTY_CN_NAME = byteArrayOf(
    0x30, 0x0B, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x00,
)

// [0] EXPLICIT INTEGER 2 (X.509 v3)
private val X509_V3_VERSION = byteArrayOf(0xA0.toByte(), 0x03, 0x02, 0x01, 0x02)

private val UTC_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC)

data class TempCertKey(
    val privateKey: PrivateKey,
    val rawPrivateKey: ByteArray,
    val publicKey: ByteArray,
    val signedCert: ByteArray,
)

private val tmpCertKey: TempCertKey by lazy {
    val keyPair = KeyPairGenerator.getInstance(JCA_SIG_ALG_ED25519).generateKeyPair()
    val privateKey = keyPair.private
    val publicKey = keyPair.public

    val privEncoded = privateKey.encoded
    val rawSeed = privEncoded.copyOfRange(privEncoded.size - ED25519_KEY_SIZE_BYTES, privEncoded.size)
    val pubEncoded = publicKey.encoded
    val rawPublic = pubEncoded.copyOfRange(pubEncoded.size - ED25519_KEY_SIZE_BYTES, pubEncoded.size)

    val serialNumber = BigInteger(159, globalSecureRandom)
    val notBeforeMillis = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1 + globalSecureRandom.nextInt(30).toLong())
    val notAfterMillis = notBeforeMillis + TimeUnit.DAYS.toMillis(90)

    val tbsCert = derSequence(
        X509_V3_VERSION,
        derInteger(serialNumber.toByteArray()),
        ED25519_ALG_ID,
        EMPTY_CN_NAME,
        derSequence(derUtcTime(notBeforeMillis), derUtcTime(notAfterMillis)),
        EMPTY_CN_NAME,
        pubEncoded,
    )

    val signature = Signature.getInstance(JCA_SIG_ALG_ED25519).run {
        initSign(privateKey, globalSecureRandom)
        update(tbsCert)
        sign()
    }
    require(signature.size == ED25519_SIGNATURE_SIZE_BYTES) {
        "Unexpected Ed25519 signature length: ${signature.size}"
    }

    val cert = derSequence(
        tbsCert,
        ED25519_ALG_ID,
        derBitString(signature),
    )

    TempCertKey(
        privateKey = privateKey,
        rawPrivateKey = rawSeed + rawPublic,
        publicKey = rawPublic,
        signedCert = cert,
    )
}

fun applyAuthKeySignature(
    authKey: ByteArray,
): CertificateData {
    require(authKey.isNotEmpty()) { "AuthKey cannot be empty" }

    val cert = tmpCertKey.signedCert.copyOf()
    val mac = Mac.getInstance("HmacSHA512")
    mac.init(SecretKeySpec(authKey, "HmacSHA512"))
    mac.update(tmpCertKey.publicKey)
    val hmac = mac.doFinal()

    System.arraycopy(hmac, 0, cert, cert.size - ED25519_SIGNATURE_SIZE_BYTES, ED25519_SIGNATURE_SIZE_BYTES)

    return CertificateData(
        certificateChain = listOf(cert),
        privateKey = tmpCertKey.privateKey,
        signatureScheme = SIGNATURE_SCHEME_ED25519,
        jcaSignatureAlgorithm = JCA_SIG_ALG_ED25519,
    )
}

private fun derTlv(tag: Int, content: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    out.write(tag)
    val len = content.size
    when {
        len < 128 -> out.write(len)
        len < 256 -> {
            out.write(0x81)
            out.write(len)
        }
        else -> {
            out.write(0x82)
            out.write((len ushr 8) and 0xFF)
            out.write(len and 0xFF)
        }
    }
    out.write(content)
    return out.toByteArray()
}

private fun derSequence(vararg items: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    items.forEach(out::write)
    return derTlv(0x30, out.toByteArray())
}

private fun derInteger(bytes: ByteArray): ByteArray = derTlv(0x02, bytes)

private fun derBitString(bytes: ByteArray): ByteArray = derTlv(0x03, byteArrayOf(0x00) + bytes)

private fun derUtcTime(epochMillis: Long): ByteArray =
    derTlv(0x17, UTC_TIME_FORMATTER.format(Instant.ofEpochMilli(epochMillis)).toByteArray(Charsets.US_ASCII))
