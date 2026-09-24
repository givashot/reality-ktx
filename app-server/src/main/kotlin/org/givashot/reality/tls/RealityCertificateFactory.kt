package org.givashot.reality.tls

import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.givashot.tls.ServerCertificateCredentials
import org.givashot.tls.globalSecureRandom
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.util.Date
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// TLS 1.3 SignatureScheme.ed25519 = 0x0807
private const val SIGNATURE_SCHEME_ED25519 = 0x0807
private const val JCA_SIG_ALG_ED25519 = "Ed25519"

private const val ED25519_KEY_SIZE_BYTES = 32
private const val ED25519_SIGNATURE_SIZE_BYTES = 64


data class TempCertKey(
    val privateKey: PrivateKey,
    val rawPrivateKey: ByteArray,
    val publicKey: ByteArray,
    val signedCert: ByteArray,
)

private fun ensureBouncyCastleProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
        Security.addProvider(BouncyCastleProvider())
    }
}

private val tmpCertKey: TempCertKey by lazy {
    ensureBouncyCastleProvider()

    val keyPair = KeyPairGenerator.getInstance(JCA_SIG_ALG_ED25519, BouncyCastleProvider.PROVIDER_NAME)
        .generateKeyPair()
    val privateKey = keyPair.private
    val publicKey = keyPair.public
    val rawPrivate = extractRawEd25519Private(privateKey, publicKey)
    val rawPublic = rawPrivate.copyOfRange(ED25519_KEY_SIZE_BYTES, ED25519_KEY_SIZE_BYTES * 2)

    val serialNumber = BigInteger(159, globalSecureRandom)
    val subject = X500Name("CN=") // 空 CN，内容无所谓
    val notBefore = Date(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1 + globalSecureRandom.nextInt(30).toLong()))
    val notAfter = Date(notBefore.time + TimeUnit.DAYS.toMillis(90))

    val certBuilder = JcaX509v3CertificateBuilder(
        subject, // issuer == subject，自签名
        serialNumber,
        notBefore,
        notAfter,
        subject,
        publicKey,
    )

    val signer = JcaContentSignerBuilder(JCA_SIG_ALG_ED25519)
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .build(privateKey)

    TempCertKey(
        privateKey = privateKey,
        rawPrivateKey = rawPrivate,
        publicKey = rawPublic,
        signedCert = certBuilder.build(signer).encoded,
    )
}

fun applyAuthKeySignature(
    authKey: ByteArray,
): ServerCertificateCredentials {
    require(authKey.isNotEmpty()) { "AuthKey cannot be empty" }

    val cert = tmpCertKey.signedCert.copyOf()
    val mac = Mac.getInstance("HmacSHA512")
    mac.init(SecretKeySpec(authKey, "HmacSHA512"))
    mac.update(tmpCertKey.publicKey)
    val hmac = mac.doFinal()

    System.arraycopy(hmac, 0, cert, cert.size - ED25519_SIGNATURE_SIZE_BYTES, ED25519_SIGNATURE_SIZE_BYTES)

    return ServerCertificateCredentials(
        certificateChain = listOf(cert),
        privateKey = tmpCertKey.privateKey,
        signatureScheme = SIGNATURE_SCHEME_ED25519,
        jcaSignatureAlgorithm = JCA_SIG_ALG_ED25519,
    )
}

private fun extractRawEd25519Private(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
    val privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.encoded)
    var seed = ASN1OctetString.getInstance(privateKeyInfo.parsePrivateKey()).octets
    if (seed.size != ED25519_KEY_SIZE_BYTES) {
        seed = ASN1OctetString.getInstance(seed).octets
    }
    require(seed.size == ED25519_KEY_SIZE_BYTES) {
        "Unexpected Ed25519 private key seed length: ${seed.size}"
    }

    val publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.encoded)
    val rawPublicKey = publicKeyInfo.publicKeyData.bytes
    require(rawPublicKey.size == ED25519_KEY_SIZE_BYTES) {
        "Unexpected Ed25519 public key length: ${rawPublicKey.size}"
    }

    return seed + rawPublicKey
}