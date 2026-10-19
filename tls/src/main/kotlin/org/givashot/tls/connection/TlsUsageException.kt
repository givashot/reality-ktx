package org.givashot.tls.connection

import org.givashot.tls.state.TlsAlert

abstract class TlsUsageException(replyAlertRecord: ByteArray) : RuntimeException() {
    abstract val description: String
    val replyAlert = TlsAlert.INTERNAL_ERROR
}

class TlsUsageInvalidStateException(val operation: String, val state: String, replyAlertRecord: ByteArray) :
    TlsUsageException(replyAlertRecord) {
    override val description: String
        get() = "$operation is not valid in state $state"
}

class TlsUsageInvalidArgumentException(val reason: String, replyAlertRecord: ByteArray) :
    TlsUsageException(replyAlertRecord) {
    override val description: String
        get() = reason
}