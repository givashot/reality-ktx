package org.givashot.tls.record

import org.givashot.tls.crypto.TrafficKeys

internal sealed interface ReadProtection {
    data object Plaintext : ReadProtection
    class Encrypted(val keys: TrafficKeys) : ReadProtection
}

internal sealed interface WriteProtection {
    data object Plaintext : WriteProtection
    class Encrypted(val keys: TrafficKeys) : WriteProtection
}

internal class RecordState(
    var readProtection: ReadProtection = ReadProtection.Plaintext,
    var writeProtection: WriteProtection = WriteProtection.Plaintext,
    var droppedChangeCipherSpecCount: Int = 0,
)
