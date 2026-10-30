package org.givashot.tunnel.vless

import org.givashot.tunnel.vless.const.VLESS_COMMAND_TYPE_MUX
import org.givashot.tunnel.vless.const.VLESS_COMMAND_TYPE_TCP
import org.givashot.tunnel.vless.const.VLESS_COMMAND_TYPE_UDP
import org.givashot.tunnel.vless.const.VLESS_FLOW_NONE
import org.givashot.tunnel.vless.const.VLESS_FLOW_XTLS_RPRX_VISION

/**
 * Decides whether a request's flow is acceptable, following the checks Xray's VLESS inbound applies to the
 * flow of a request and of the account it authenticated as.
 *
 * @property allowedFlows the flows this server accepts. The empty flow stands for a plain VLESS stream; leaving it
 * out of the set requires every TCP request to use a flow, the way an account bound to a flow does in Xray.
 */
class VlessFlowPolicy(val allowedFlows: Set<String> = setOf(VLESS_FLOW_NONE, VLESS_FLOW_XTLS_RPRX_VISION)) {

    init {
        require(KNOWN_FLOWS.containsAll(allowedFlows)) { "Unknown VLESS flows: ${allowedFlows - KNOWN_FLOWS}" }
    }

    /** @return the reason the request must be rejected, or null when it is acceptable. */
    fun check(header: VlessRequestHeader): String? = check(header.flow, header.command)

    fun check(flow: String, command: Int): String? = when {
        flow !in KNOWN_FLOWS -> "unknown VLESS flow '$flow'"
        flow == VLESS_FLOW_XTLS_RPRX_VISION && command == VLESS_COMMAND_TYPE_UDP ->
            "VLESS flow '$flow' does not support UDP"

        flow in allowedFlows -> null
        // Xray still lets UDP through without a flow, since such a stream is not a TLS-in-TLS tunnel.
        flow == VLESS_FLOW_NONE ->
            if (command == VLESS_COMMAND_TYPE_TCP || command == VLESS_COMMAND_TYPE_MUX) "VLESS flow is required" else null

        else -> "VLESS flow '$flow' is not allowed"
    }

    private companion object {
        val KNOWN_FLOWS = setOf(VLESS_FLOW_NONE, VLESS_FLOW_XTLS_RPRX_VISION)
    }
}
