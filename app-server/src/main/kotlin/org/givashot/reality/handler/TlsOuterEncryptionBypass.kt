package org.givashot.reality.handler

/**
 * Implemented by the handler that owns the outer TLS layer, so that a handler above it can ask to leave the layer
 * once the proxied traffic is itself TLS, as XTLS Vision's direct copy does. Both calls happen on the channel's
 * event loop and are irreversible.
 */
interface TlsOuterEncryptionBypass {

    /**
     * Stops decrypting what the peer sends: from now on received bytes are passed up as they are. Bytes that were
     * already received but not yet decrypted must be passed up first, in order. May be called from within the
     * `channelRead` that delivered the last decrypted data.
     */
    fun stopDecrypting()

    /**
     * Stops encrypting what is written: writes that follow the current one go to the socket as they are. Called
     * right after the last write that must still be encrypted, so that write has to be encrypted synchronously.
     * No close_notify may be sent afterwards, since the peer no longer reads TLS records.
     */
    fun stopEncrypting()
}
