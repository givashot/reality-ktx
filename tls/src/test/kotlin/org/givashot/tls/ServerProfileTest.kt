package org.givashot.tls

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ServerProfileTest {
    @Test
    fun `default profile matches existing behavior`() {
        val profile = ServerProfile(recordLengths = listOf(128, 256))
        assertEquals(ServerProfile.DEFAULT_CIPHER_SUITES, profile.cipherSuites)
        assertEquals(ServerProfile.CipherSelectionMode.CLIENT_PREFERENCE, profile.cipherSelection)
        assertEquals(false, profile.sendChangeCipherSpec)
        assertEquals(null, profile.extensionOrder)
    }

    @Test
    fun `invalid profile values fail fast`() {
        assertFailsWith<IllegalArgumentException> {
            ServerProfile(recordLengths = emptyList())
        }
        assertFailsWith<IllegalArgumentException> {
            ServerProfile(recordLengths = listOf(128), sendChangeCipherSpec = true)
        }
        assertFailsWith<IllegalArgumentException> {
            ServerProfile(recordLengths = listOf(128), extensionOrder = listOf(1))
        }
    }
}
