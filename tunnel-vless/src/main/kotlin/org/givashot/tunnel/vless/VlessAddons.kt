package org.givashot.tunnel.vless

import org.givashot.tunnel.vless.const.VLESS_FLOW_XTLS_RPRX_VISION

/**
 * The decoded addons of a VLESS request header, mirroring Xray's `Addons` protobuf message.
 *
 * @property flow the flow name, empty when the client requests none, for example [VLESS_FLOW_XTLS_RPRX_VISION].
 * @property seed the opaque seed bytes, empty when absent. Preserved as sent and not interpreted.
 */
class VlessAddons(
    val flow: String = "",
    val seed: ByteArray = EMPTY_BYTES,
) {

    val isVision: Boolean get() = flow == VLESS_FLOW_XTLS_RPRX_VISION

    override fun equals(other: Any?): Boolean =
        this === other || (other is VlessAddons && flow == other.flow && seed.contentEquals(other.seed))

    override fun hashCode(): Int = 31 * flow.hashCode() + seed.contentHashCode()

    override fun toString(): String = "VlessAddons(flow='$flow', seed=${seed.size} bytes)"

    companion object {
        private val EMPTY_BYTES = ByteArray(0)

        val EMPTY = VlessAddons()
    }
}
