package org.givashot.tls.crypto

import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.XECPublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.KeyAgreement

// RFC 8410 DER prefixes for 32-byte raw X25519 keys
private val X25519_PKCS8_PREFIX = byteArrayOf(
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20,
)

private val X25519_X509_PREFIX = byteArrayOf(
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
    0x6E, 0x03, 0x21, 0x00,
)

private fun x25519KeyFactory(): KeyFactory = KeyFactory.getInstance("X25519")

private fun ByteArray.toX25519PrivateKey() =
    x25519KeyFactory().generatePrivate(PKCS8EncodedKeySpec(X25519_PKCS8_PREFIX + this))

private fun ByteArray.toX25519PublicKey() =
    x25519KeyFactory().generatePublic(X509EncodedKeySpec(X25519_X509_PREFIX + this))

/**
 * 使用 JDK JCA 生成 32 字节安全的 X25519 随机私钥
 */
fun generateX25519PrivateKey(): ByteArray {
    val kpg = KeyPairGenerator.getInstance("X25519")
    kpg.initialize(NamedParameterSpec.X25519, globalSecureRandom)
    val encoded = kpg.generateKeyPair().private.encoded
    return encoded.copyOfRange(encoded.size - 32, encoded.size)
}

/**
 * 从 32 字节 X25519 私钥推导出 32 字节公钥
 * @return 32 字节公钥 (c_pk)
 */
fun ByteArray.deriveX25519PublicKey(): ByteArray {
    require(size == 32) { "X25519 private key must be 32 bytes" }
    val priv = toX25519PrivateKey()
    // RFC 7748: X25519(k, u=9)
    val basePoint = ByteArray(32).apply { this[0] = 9 }
    return KeyAgreement.getInstance("X25519").run {
        init(priv)
        doPhase(basePoint.toX25519PublicKey(), true)
        generateSecret()
    }
}

/**
 * 使用 JDK JCA 计算 X25519 共享密钥 (Shared Secret)
 * for client: shared_secret = c_sk * s_pk = c_sk * (s_sk * g)
 * for server: shared_secret = s_sk * c_pk = s_sk * (c_sk * g)
 */
fun calcSharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
    require(privateKey.size == 32) { "X25519 private key must be 32 bytes" }
    require(publicKey.size == 32) { "X25519 public key must be 32 bytes" }
    return KeyAgreement.getInstance("X25519").run {
        init(privateKey.toX25519PrivateKey())
        doPhase(publicKey.toX25519PublicKey(), true)
        generateSecret()
    }
}

fun x25519PublicKeyFromBase64(value: String): ByteArray {
    val decoded = runCatching { Base64.getUrlDecoder().decode(value) }
        .getOrElse { Base64.getDecoder().decode(value) }

    val rawPublicKeyBytes: ByteArray = when (decoded.size) {
        32 -> decoded
        else -> {
            val pubKey = x25519KeyFactory().generatePublic(X509EncodedKeySpec(decoded))
            check(pubKey is XECPublicKey) { "Not an X25519 public key" }
            val encoded = pubKey.encoded
            require(encoded.size >= 32) { "Invalid X25519 SPKI key length: ${encoded.size}" }
            encoded.copyOfRange(encoded.size - 32, encoded.size)
        }
    }

    require(rawPublicKeyBytes.size == 32) {
        "Invalid X25519 public key length: ${rawPublicKeyBytes.size}, expected 32 bytes"
    }
    // 校验公钥合法性
    rawPublicKeyBytes.toX25519PublicKey()
    return rawPublicKeyBytes
}

fun x25519PrivateKeyFromBase64(value: String): ByteArray {
    val decoded = runCatching { Base64.getUrlDecoder().decode(value) }
        .getOrElse { Base64.getDecoder().decode(value) }

    require(decoded.size == 32) {
        "Invalid X25519 private key length: ${decoded.size}, expected 32 bytes"
    }
    decoded.toX25519PrivateKey()
    return decoded
}
