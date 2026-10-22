package org.givashot.tls.connection

abstract class TlsUsageException(val replyAlertRecord: ByteArray) : Exception() {
    abstract val description: String

    override val message: String?
        get() = description
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