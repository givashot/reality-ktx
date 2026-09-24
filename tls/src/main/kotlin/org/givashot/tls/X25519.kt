package org.givashot.tls

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.util.*

/**
 * 使用 BouncyCastle 生成 32 字节安全的 X25519 随机私钥
 */
fun generateX25519PrivateKey(): ByteArray {
    // 自动通过 SecureRandom 填充安全随机数并创建私钥参数
    val privKeyParams = X25519PrivateKeyParameters(globalSecureRandom)
    // 导出 32 字节原始私钥数组
    return privKeyParams.encoded
}

/**
 * 从 32 字节 X25519 私钥推导出 32 字节公钥
 * @return 32 字节公钥 (c_pk)
 */
fun ByteArray.deriveX25519PublicKey(): ByteArray {
    val privateKey = this
    require(privateKey.size == 32) { "X25519 private key must be 32 bytes" }
    return X25519PrivateKeyParameters(privateKey, 0).generatePublicKey().encoded
}

/**
 * 使用 BouncyCastle 计算 X25519 共享密钥 (Shared Secret)
 * for client: shared_secret = c_sk * s_pk = c_sk * (s_sk * g)
 * for server: shared_secret = s_sk * c_pk = s_sk * (c_sk * g)
 */
fun calcSharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
    require(privateKey.size == 32) { "X25519 private key must be 32 bytes" }
    require(publicKey.size == 32) { "X25519 public key must be 32 bytes" }
    // 1. 构建 BouncyCastle 私钥参数对象
    val privParams = X25519PrivateKeyParameters(privateKey, 0)
    // 2. 构建 BouncyCastle 公钥参数对象
    val pubParams = X25519PublicKeyParameters(publicKey, 0)
    // 3. 执行 ECDH (标量乘法)，导出 32 字节共享密钥
    val sharedSecret = ByteArray(32)
    privParams.generateSecret(pubParams, sharedSecret, 0)
    return sharedSecret
}

fun x25519PublicKeyFromBase64(value: String): ByteArray {
    // 1. 兼容 Base64 和 Base64URL 解码
    val decoded = runCatching { Base64.getUrlDecoder().decode(value) }
        .getOrElse { Base64.getDecoder().decode(value) }

    val rawPublicKeyBytes: ByteArray = when (decoded.size) {
        // 情况 A：标准的 32 字节裸公钥（REALITY 配置中最常见）
        32 -> decoded

        // 情况 B：标准 X.509/SubjectPublicKeyInfo 编码格式（通常 44 字节）
        // 使用 BouncyCastle 的 ASN.1 解析器零解析提取，不再需要手动拼接 Prefix
        else -> {
            val spki = SubjectPublicKeyInfo.getInstance(decoded)
            // 提取出内部的 32 字节原始公钥
            spki.publicKeyData.bytes
        }
    }

    require(rawPublicKeyBytes.size == 32) {
        "Invalid X25519 public key length: ${rawPublicKeyBytes.size}, expected 32 bytes"
    }

    // 2. 使用 BouncyCastle 的 X25519PublicKeyParameters 进行安全校验并导出
    val publicKeyParams = X25519PublicKeyParameters(rawPublicKeyBytes, 0)
    return publicKeyParams.encoded
}

fun x25519PrivateKeyFromBase64(value: String): ByteArray {
    // 1. 兼容 Base64 和 Base64URL 解码
    val decoded = runCatching { Base64.getUrlDecoder().decode(value) }
        .getOrElse { Base64.getDecoder().decode(value) }

    val rawPublicKeyBytes: ByteArray = when (decoded.size) {
        // 情况 A：标准的 32 字节裸公钥（REALITY 配置中最常见）
        32 -> decoded

        // 情况 B：标准 X.509/SubjectPublicKeyInfo 编码格式（通常 44 字节）
        // 使用 BouncyCastle 的 ASN.1 解析器零解析提取，不再需要手动拼接 Prefix
        else -> {
            val spki = SubjectPublicKeyInfo.getInstance(decoded)
            // 提取出内部的 32 字节原始公钥
            spki.publicKeyData.bytes
        }
    }

    require(rawPublicKeyBytes.size == 32) {
        "Invalid X25519 public key length: ${rawPublicKeyBytes.size}, expected 32 bytes"
    }

    // 2. 使用 BouncyCastle 的 X25519PublicKeyParameters 进行安全校验并导出
    val publicKeyParams = X25519PrivateKeyParameters(rawPublicKeyBytes, 0)
    return publicKeyParams.encoded
}
