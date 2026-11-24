package org.givashot.utils

import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.*

internal data class VlessNode(
    val uuid: String,
    val host: String,
    val port: Int,
    val publicKey: String,
    val shortId: String,
    val serverName: String,
    val name: String,
    val mode: String = "multi",
    val security: String = "reality",
    val encryption: String = "none",
    val type: String = "tcp",
    val flow: String = "xtls-rprx-vision",
    val spiderX: String = "/",
    val fingerprint: String = "chrome",
) {
    fun toUri(): String {
        fun encode(value: String) =
            URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

        val parameters = listOf(
            "mode" to mode,
            "security" to security,
            "encryption" to encryption,
            "type" to type,
            "flow" to flow,
            "pbk" to publicKey,
            "sid" to shortId,
            "sni" to serverName,
            "servername" to serverName,
            "spx" to spiderX,
            "fp" to fingerprint,
        ).joinToString("&") { (key, value) -> "$key=${encode(value)}" }
        return "vless://$uuid@$host:$port?$parameters#${encode(name)}"
    }
}

internal fun encodeSubscription(content: String): String =
    Base64.getEncoder().encodeToString(content.toByteArray(StandardCharsets.UTF_8))

fun main() {
    val uuid = "33094c7a-2179-4736-9ff0-a2cb5ed2db57"
    val host = "reality-test-nlb-72de873f203e688e.elb.ap-east-2.amazonaws.com"
    val port = 443
    val publicKey = "BibSh9unULvd69pRrI_aRA8i1x4NmTPnrtj4_GKeCGA"
    val shortId = "98653321"
    val serverName = "httpbin.org"
    val name = "台湾#1"

    val node = VlessNode(uuid, host, port, publicKey, shortId, serverName, name)
    val uri = node.toUri()
    println(uri)
    println(encodeSubscription(uri))
}