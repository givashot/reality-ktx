package org.givashot.tls.state

enum class TlsAlert(val code: Int) {
    // if receive a close notify, we should send a close notify to peer, then close connection
    CLOSE_NOTIFY(0),

    // directly close connection
    USER_CANCELED(90),

    /* FATAL ALERT BEGIN */
    // directly close connection
    UNEXPECTED_MESSAGE(10),
    BAD_RECORD_MAC(20),
    HANDSHAKE_FAILURE(40),
    ILLEGAL_PARAMETER(47),
    DECODE_ERROR(50),
    DECRYPT_ERROR(51),
    INTERNAL_ERROR(80);
    /* FATAL ALERT END */
}
