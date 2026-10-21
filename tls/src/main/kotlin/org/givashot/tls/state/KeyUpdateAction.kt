package org.givashot.tls.state

/** What the state machine decided to do about a received KeyUpdate. */
enum class KeyUpdateAction {
    /** Nothing to send back. */
    None,

    /** The peer asked for an update: answer with our own KeyUpdate (update_not_requested). */
    Reply,
}
