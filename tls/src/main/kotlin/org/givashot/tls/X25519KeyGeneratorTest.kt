package org.givashot.tls

import java.util.*

/**
 * Gen x25519 priv pub base64 pair
 *
 * @return the pair which first priv second pub
 */
private fun genX25519PrivPubBase64Pair(): Pair<String, String> {
    val rawPrivKey = generateX25519PrivateKey()
    val rawPubKey = rawPrivKey.deriveX25519PublicKey()
    val encoder = Base64.getUrlEncoder().withoutPadding()
    return encoder.encodeToString(rawPrivKey) to encoder.encodeToString(rawPubKey)
}

fun main() {
    val keyPair = genX25519PrivPubBase64Pair()
    println("Private Key: ${keyPair.first}")
    println("Public Key : ${keyPair.second}")
}