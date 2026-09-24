package org.givashot.appclient

import org.bouncycastle.tls.TlsExtensionsUtils
import org.givashot.appclient.ext.toHexByteArrayPadded
import org.givashot.appclient.tls.ClientHelloBuilder
import org.givashot.appclient.tls.ClientHelloOptions
import org.givashot.appclient.tls.RealityCrypto.calculateAuthKey
import org.givashot.appclient.tls.RealityCrypto.encryptSessionId
import org.givashot.appclient.tls.encodeTLSRecord
import org.givashot.tls.calcSharedSecret
import org.givashot.tls.deriveX25519PublicKey
import org.givashot.tls.generateX25519PrivateKey
import org.givashot.tls.x25519PublicKeyFromBase64
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors

private const val DEFAULT_HOST = "127.0.0.1"
private const val DEFAULT_PORT = 443

// uXJ_anIK9lCiIET24chyh87HLIsMaEc4xfC1IVTI8QI
private const val SERVER_PK = "Kgb_c9qdU_b86QsfIQci64X6ujFOA4MkeGIk3hq-Rlw"

private const val SERVER_SHORT_ID = "thx-birth"

fun main() {
    val executors = Executors.newSingleThreadExecutor()
    executors.execute {
        request2Server(
            InetSocketAddress(DEFAULT_HOST, DEFAULT_PORT),
            buildNormalTLSRecord()
        )
    }
    executors.execute {
        request2Server(
            InetSocketAddress(DEFAULT_HOST, DEFAULT_PORT),
            buildRealityTLSRecord()
        )
    }
}

fun request2Server(socketAddress: InetSocketAddress, record: ByteArray) {
    println("Connecting to ${socketAddress.hostName}:${socketAddress.port}")
    println("Sending ClientHello (${record.size} bytes)")
    println(record.contentToString())

    try {
        Socket().use { socket ->
            socket.connect(socketAddress, 20_000)
            socket.soTimeout = 20_000

            socket.getOutputStream().use { output ->
                output.write(record)
                output.flush()

                socket.getInputStream().use { input ->
                    val response = input.readBytes()
                    println("Received ${response.size} bytes")
                    if (response.isNotEmpty()) {
                        println(response.toHexString())
                    }
                }
            }
        }
    } catch (e: Exception) {
        println("Exception while connecting to ${socketAddress.hostName}:${socketAddress.port}, msg = ${e.message}")
    }
}

fun buildNormalTLSRecord(): ByteArray {
    val normalOptions = ClientHelloOptions(
        sni = "localhost",
    )
    return ClientHelloBuilder.build(normalOptions).encodeTLSRecord()
}

fun buildRealityTLSRecord(): ByteArray {
    val cskRandom = generateX25519PrivateKey()
    val cpk = cskRandom.deriveX25519PublicKey()
    val sharedSecret = calcSharedSecret(cskRandom, x25519PublicKeyFromBase64(SERVER_PK))
    val realityOptions = ClientHelloOptions(
        sni = "localhost",
        extensions = mapOf(
            TlsExtensionsUtils.EXT_key_share to
                    ClientHelloBuilder.createX25519KeyShareExtension(cpk),
        ),
    )
    val realityClientHello = ClientHelloBuilder.build(realityOptions)
    val realityTLSRecord = realityClientHello.encodeTLSRecord()
    val authKey = calculateAuthKey(sharedSecret, realityClientHello.random)
    val sessionId = encryptSessionId(
        authKey,
        realityClientHello.random,
        SERVER_SHORT_ID.toHexByteArrayPadded(),
        realityTLSRecord.copyOfRange(5, realityTLSRecord.size),
        4 + 2 + 32 + 1
    )
    sessionId.copyInto(realityTLSRecord, 5 + 4 + 2 + 32 + 1)
    return realityTLSRecord
}


