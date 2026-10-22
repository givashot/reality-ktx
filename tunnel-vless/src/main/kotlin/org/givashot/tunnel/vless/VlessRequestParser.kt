package org.givashot.tunnel.vless

import org.givashot.tunnel.vless.const.VLESS_ADDRESS_TYPE_DOMAIN
import org.givashot.tunnel.vless.const.VLESS_ADDRESS_TYPE_IPV4
import org.givashot.tunnel.vless.const.VLESS_ADDRESS_TYPE_IPV6
import org.givashot.tunnel.vless.const.VLESS_ADDRESS_TYPE_DOMAIN_LENGTH_DESC
import org.givashot.tunnel.vless.const.VLESS_ADDRESS_TYPE_IPV4_LENGTH
import org.givashot.tunnel.vless.const.VLESS_ADDRESS_TYPE_IPV6_LENGTH
import org.givashot.tunnel.vless.const.VLESS_ADDRESS_TYPE_LENGTH
import org.givashot.tunnel.vless.const.VLESS_ADD_ON_LENGTH_DESC
import org.givashot.tunnel.vless.const.VLESS_COMMAND_LENGTH
import org.givashot.tunnel.vless.const.VLESS_PORT_LENGTH
import org.givashot.tunnel.vless.const.VLESS_UUID_LENGTH
import java.net.InetAddress

/**
 * Parses a VLESS request header from accumulated bytes.
 *
 * Layout: version (1) | UUID (16) | addons length (1) | addons | command (1) | port (2, big-endian) |
 * address type (1) | address. Every field is returned as sent; validation is left to the caller.
 */
object VlessRequestParser {

    /**
     * Returns [VlessParseResult.NeedMoreData] when [input] is a valid prefix but not yet a full header, and
     * [VlessParseResult.Complete] with the number of consumed bytes once the header is fully present.
     *
     * @throws VlessProtocolException when the address type is unknown, since the address length cannot be determined.
     */
    fun parse(input: ByteArray): VlessParseResult {
        val version = input[0]
        var offset = 1
        if (input.size < offset + VLESS_UUID_LENGTH) return VlessParseResult.NeedMoreData
        val uuid = input.copyOfRange(1, 1 + VLESS_UUID_LENGTH).also { offset += VLESS_UUID_LENGTH }
        if (input.size < offset + VLESS_ADD_ON_LENGTH_DESC) return VlessParseResult.NeedMoreData
        val addonsLength = input[offset].unsigned().also { offset += VLESS_ADD_ON_LENGTH_DESC }
        if (input.size < offset + addonsLength) return VlessParseResult.NeedMoreData
        val addons = input.copyOfRange(offset, offset + addonsLength).also { offset += addonsLength }
        if (input.size < offset + VLESS_COMMAND_LENGTH) return VlessParseResult.NeedMoreData
        val command = input[offset].unsigned().also { offset += VLESS_COMMAND_LENGTH }
        if (input.size < offset + VLESS_PORT_LENGTH) return VlessParseResult.NeedMoreData
        val port = ((input[offset].unsigned() shl 8) or input[offset + 1].unsigned()).also { offset += VLESS_PORT_LENGTH }
        if (input.size < offset + VLESS_ADDRESS_TYPE_LENGTH) return VlessParseResult.NeedMoreData
        val addressType = input[offset].unsigned().also { offset += VLESS_ADDRESS_TYPE_LENGTH }
        val host: String
        when (addressType) {
            VLESS_ADDRESS_TYPE_IPV4 -> {
                if (input.size < offset + VLESS_ADDRESS_TYPE_IPV4_LENGTH) return VlessParseResult.NeedMoreData
                host = InetAddress.getByAddress(input.copyOfRange(offset, offset + 4)).hostAddress
                    .also { offset += VLESS_ADDRESS_TYPE_IPV4_LENGTH }
            }

            VLESS_ADDRESS_TYPE_DOMAIN -> {
                if (input.size < offset + VLESS_ADDRESS_TYPE_DOMAIN_LENGTH_DESC) return VlessParseResult.NeedMoreData
                val domainLength = input[offset].unsigned().also { offset += VLESS_ADDRESS_TYPE_DOMAIN_LENGTH_DESC }
                if (input.size < offset + domainLength) return VlessParseResult.NeedMoreData
                host = String(input, offset, domainLength, Charsets.UTF_8).also { offset += domainLength }
            }

            VLESS_ADDRESS_TYPE_IPV6 -> {
                if (input.size < offset + VLESS_ADDRESS_TYPE_IPV6_LENGTH) return VlessParseResult.NeedMoreData
                host = InetAddress.getByAddress(input.copyOfRange(offset, offset + 16)).hostAddress
                    .also { offset += VLESS_ADDRESS_TYPE_IPV6_LENGTH }
            }

            else -> throw VlessProtocolException("Unknown VLESS address type: $addressType")
        }

        return VlessParseResult.Complete(VlessRequestHeader(version, uuid, addons, command, host, port), offset)
    }

    private fun Byte.unsigned(): Int = toInt() and 0xFF
}

sealed interface VlessParseResult {

    data object NeedMoreData : VlessParseResult

    /** [consumed] is the number of bytes of the input that belong to the header. */
    data class Complete(val header: VlessRequestHeader, val consumed: Int) : VlessParseResult
}
