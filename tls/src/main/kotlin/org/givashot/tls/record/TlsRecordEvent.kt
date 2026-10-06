package org.givashot.tls.record

/** What the record layer produced for one inbound record. Legality in the current protocol state is not decided here. */
internal sealed interface TlsRecordEvent {
    /** A record with a non-empty payload; [type] is the inner content type for protected records. */
    class Content(val type: Int, val payload: ByteArray) : TlsRecordEvent

    /** A record whose (inner) payload is empty. */
    data class Empty(val type: Int) : TlsRecordEvent

    /** A well-formed ChangeCipherSpec record (RFC 8446 appendix D.4). */
    data object CompatibilityCcs : TlsRecordEvent
}
