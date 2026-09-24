package org.givashot.reality.authentication

import org.givashot.reality.config.RealityConfig
import org.givashot.reality.ext.toHexByteArrayPadded
import org.givashot.reality.tls.ByteArrayKey
import org.givashot.tls.ClientHelloWrapper
import org.givashot.reality.tls.RealityCrypto
import org.givashot.tls.calcSharedSecret
import org.givashot.tls.x25519PrivateKeyFromBase64
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.abs

sealed interface AuthResult {
    @Suppress("ArrayInDataClass")
    data class Success(val authKey: ByteArray) : AuthResult
    data class Failure(val reason: Any? = null) : AuthResult
}

class Authenticator(
    realityConfig: RealityConfig,
) {

    private val acceptableSnis = realityConfig.acceptableSnis.toTypedArray()

    private val serverPrivateKey = realityConfig.privateKey
        .takeIf { it.isNotBlank() }
        ?.let(::x25519PrivateKeyFromBase64) ?: throw IllegalArgumentException("private key is missing")

    private val expectedShortIds = realityConfig.shortIds.map {
        ByteArrayKey(it.toHexByteArrayPadded())
    }.toTypedArray()

    private val allowedClockSkewSeconds = realityConfig.allowedClockSkewSeconds

    fun doAuth(clientHelloWrapper: ClientHelloWrapper): AuthResult {
        var authFailed = true
        var authKey: ByteArray? = null
        try {
            val sni = clientHelloWrapper.sni ?: throw Exception("sni is missing")
            if (sni in acceptableSnis) {
                val clientPK = clientHelloWrapper.clientPubKey ?: throw Exception("Client public key is missing")
                val sharedSecret = calcSharedSecret(serverPrivateKey, clientPK)
                authKey = RealityCrypto.calculateAuthKey(sharedSecret, clientHelloWrapper.base.random)
                val plaintext = RealityCrypto.decryptSessionId(
                    authKey = authKey,
                    clientHelloWrapper = clientHelloWrapper,
                )
                val timestamp = ByteBuffer.wrap(plaintext, 4, 4).order(ByteOrder.BIG_ENDIAN).int.toLong() and 0xffffffffL
                val nowSeconds = System.currentTimeMillis() / 1000
                if (abs(nowSeconds - timestamp) <= allowedClockSkewSeconds) {
                    val shortId = plaintext.copyOfRange(8, 16)
                    if (expectedShortIds.isEmpty()
                        || ByteArrayKey(shortId) in expectedShortIds
                    ) {
                        // auth success
                        authFailed = false
                    }
                }
            }
        } catch (e: Throwable) {
            println("auth failed, e.msg = ${e.message}")
        }
        return if (authFailed) {
            AuthResult.Failure()
        } else {
            AuthResult.Success(authKey!!)
        }
    }

}
