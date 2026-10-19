package org.givashot.tls.connection

import org.givashot.tls.state.TlsAlert

abstract class TlsPeerProtocolException : Exception() {
    abstract val description: String
    abstract val replyAlert: TlsAlert

    override val message: String?
        get() = description
}

open class UnexpectMessageException(val desc: String) : TlsPeerProtocolException() {
    override val description: String
        get() = desc
    override val replyAlert: TlsAlert
        get() = TlsAlert.UNEXPECTED_MESSAGE
}

class DecodeErrorException(val reason: String) : TlsPeerProtocolException() {
    override val description: String
        get() = reason
    override val replyAlert: TlsAlert
        get() = TlsAlert.DECODE_ERROR
}

class IllegalParameterException(val reason: String) : TlsPeerProtocolException() {
    override val description: String
        get() = reason
    override val replyAlert: TlsAlert
        get() = TlsAlert.ILLEGAL_PARAMETER
}

class UnexpectedRecordException(type: Int, phase: String) :
    UnexpectMessageException("Unexpected record of type $type in $phase")

class UnexpectedContentTypeException(expected: Int, actual: Int, phase: String) :
    UnexpectMessageException("Unexpected content type $actual (expected $expected) in $phase")

class UnexpectedHandshakeTypeException(expected: Int, actual: Int) :
    UnexpectMessageException("Unexpected handshake type $actual (expected $expected)")

class UnexpectedExtraHandshakeDataException(context: String): UnexpectMessageException("Unexpected extra handshake data: $context")

class NegotiationFailedException(val reason: String) : TlsPeerProtocolException() {
    override val description: String
        get() = reason
    override val replyAlert: TlsAlert
        get() = TlsAlert.HANDSHAKE_FAILURE
}

class ClientFinishedVerificationFailedException : TlsPeerProtocolException() {
    override val description: String
        get() = "Client Finished verification failed"
    override val replyAlert: TlsAlert
        get() = TlsAlert.DECRYPT_ERROR
}

class BadRecordMacException : TlsPeerProtocolException() {
    override val description: String
        get() = "Bad record mac"
    override val replyAlert: TlsAlert
        get() = TlsAlert.BAD_RECORD_MAC
}