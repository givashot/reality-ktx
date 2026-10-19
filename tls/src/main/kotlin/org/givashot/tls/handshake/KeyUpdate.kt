package org.givashot.tls.handshake

import org.givashot.tls.constant.TLS_HANDSHAKE_KEY_UPDATE_REQUESTED

data class KeyUpdate(
    val updateRequest: Int
) {
    val updateRequested: Boolean = updateRequest == TLS_HANDSHAKE_KEY_UPDATE_REQUESTED
}
