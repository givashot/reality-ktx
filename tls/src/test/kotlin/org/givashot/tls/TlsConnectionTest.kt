package org.givashot.tls

import org.givashot.tls.connection.TlsCommand
import org.givashot.tls.connection.TlsConnection
import org.givashot.tls.connection.TlsConnectionResult
import org.givashot.tls.connection.TlsError
import org.givashot.tls.connection.TlsEvent
import org.givashot.tls.constant.TLS_CONTENT_TYPE_ALERT
import org.givashot.tls.constant.TLS_CONTENT_TYPE_HANDSHAKE
import org.givashot.tls.constant.TLS_MAX_CONSECUTIVE_EMPTY_RECORDS
import org.givashot.tls.crypto.tlsHandshakeMessage
import org.givashot.tls.crypto.tlsRecord
import org.givashot.tls.handshake.EncryptedExtensionsData
import org.givashot.tls.state.TlsState
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class TlsConnectionTest {
    private val profile = ServerProfile(recordLengths = listOf(1500))

    private fun ok(result: TlsConnectionResult) = assertIs<TlsConnectionResult.Ok>(result)
    private fun err(result: TlsConnectionResult) = assertIs<TlsConnectionResult.Err>(result).error

    private fun flight() = TlsCommand.SendServerFlight(EncryptedExtensionsData(), TestTlsClient.certificate())

    private fun afterServerFlight(client: TestTlsClient, connection: TlsConnection) {
        val hello = ok(connection.receive(client.clientHelloRecord))
        assertIs<TlsEvent.ClientHello>(hello.events.single())
        val sent = ok(connection.execute(flight()))
        client.processServerFlight(sent.outbound)
        assertEquals(TlsState.AwaitClientFinished, connection.state)
    }

    private fun established(client: TestTlsClient = TestTlsClient()): Pair<TlsConnection, TestTlsClient> {
        val connection = TlsConnection.create(profile)
        afterServerFlight(client, connection)
        val finished = ok(connection.receive(client.finishedRecord()))
        assertEquals(listOf<TlsEvent>(TlsEvent.ClientFinished), finished.events)
        client.startApplicationPhase()
        assertEquals(TlsState.Established, connection.state)
        return connection to client
    }

    @Test
    fun `full handshake reaches established for every cipher suite`() {
        for (id in listOf(0x1301, 0x1302, 0x1303)) {
            established(TestTlsClient(id))
        }
    }

    @Test
    fun `application data flows both ways`() {
        val (connection, client) = established()

        val inbound = ok(connection.receive(client.encryptApplicationData("ping".toByteArray())))
        val data = assertIs<TlsEvent.ClientApplicationData>(inbound.events.single())
        assertContentEquals("ping".toByteArray(), data.data)

        val outbound = ok(connection.execute(TlsCommand.SendApplicationData("pong".toByteArray())))
        val received = outbound.outbound.flatMap { client.decryptApplicationData(it).toList() }
        assertContentEquals("pong".toByteArray(), received.toByteArray())
    }

    @Test
    fun `client KeyUpdate with request rotates both directions and gets a response`() {
        val (connection, client) = established()

        val keyUpdate = client.encryptKeyUpdate(requestPeer = true)
        val applicationData = client.encryptApplicationData("after update".toByteArray())
        val update = ok(connection.receive(keyUpdate + applicationData))
        assertEquals(1, update.outbound.size)
        assertEquals(false, client.decryptKeyUpdate(update.outbound.single()))

        assertContentEquals(
            "after update".toByteArray(),
            assertIs<TlsEvent.ClientApplicationData>(update.events.single()).data,
        )
        val outbound = ok(connection.execute(TlsCommand.SendApplicationData("reply".toByteArray())))
        assertContentEquals(
            "reply".toByteArray(),
            client.decryptApplicationData(outbound.outbound.single()),
        )
    }

    @Test
    fun `client KeyUpdate without request updates read keys without response`() {
        val (connection, client) = established()

        val update = ok(connection.receive(client.encryptKeyUpdate(requestPeer = false)))
        assertTrue(update.outbound.isEmpty())
        val inbound = ok(connection.receive(client.encryptApplicationData("updated".toByteArray())))
        assertContentEquals(
            "updated".toByteArray(),
            assertIs<TlsEvent.ClientApplicationData>(inbound.events.single()).data,
        )
    }

    @Test
    fun `server can initiate KeyUpdate and process client response`() {
        val (connection, client) = established()

        val update = ok(connection.execute(TlsCommand.SendKeyUpdate(requestPeer = true)))
        assertEquals(1, update.outbound.size)
        assertEquals(false, client.decryptKeyUpdate(update.outbound.single()))
        ok(connection.receive(client.encryptKeyUpdate(requestPeer = false)))

        val outbound = ok(connection.execute(TlsCommand.SendApplicationData("new keys".toByteArray())))
        assertContentEquals("new keys".toByteArray(), client.decryptApplicationData(outbound.outbound.single()))
    }

    @Test
    fun `malformed KeyUpdate returns an encrypted fatal alert`() {
        val (connection, client) = established()
        val result = connection.receive(client.encryptMalformedKeyUpdate(byteArrayOf(2)))
        assertEquals(TlsError.Peer.InvalidKeyUpdateRequest, err(result))
        val outbound = assertIs<TlsConnectionResult.Err>(result).outbound
        assertEquals(1, outbound.size)
        assertContentEquals(byteArrayOf(2, 47), client.decryptAlert(outbound.single()))
    }

    @Test
    fun `ClientHello without TLS 1_3 support is returned for fallback`() {
        val client = TestTlsClient()
        val hello = TestTlsClient.buildClientHello(client.publicKey, tls13Supported = false)
        val record = tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, hello)
        val connection = TlsConnection.create(profile)

        assertIs<TlsError.Peer.NegotiationFailed>(err(connection.receive(record)))
        assertContentEquals(record, connection.unauthenticatedInboundBytes())
    }

    @Test
    fun `ClientHello without X25519 key share is returned for fallback`() {
        val client = TestTlsClient()
        val hello = TestTlsClient.buildClientHello(client.publicKey, includeX25519KeyShare = false)
        val record = tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, hello)
        val connection = TlsConnection.create(profile)

        assertIs<TlsError.Peer.NegotiationFailed>(err(connection.receive(record)))
        assertContentEquals(record, connection.unauthenticatedInboundBytes())
    }

    @Test
    fun `ClientHello with only a non X25519 key share is returned for fallback`() {
        val client = TestTlsClient()
        val hello = TestTlsClient.buildClientHello(client.publicKey, keyShareGroup = 23)
        val record = tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, hello)
        val connection = TlsConnection.create(profile)

        assertIs<TlsError.Peer.NegotiationFailed>(err(connection.receive(record)))
        assertContentEquals(record, connection.unauthenticatedInboundBytes())
    }

    @Test
    fun `client hello split across reads is reassembled`() {
        val client = TestTlsClient()
        val connection = TlsConnection.create(profile)
        val record = client.clientHelloRecord
        assertEquals(emptyList(), ok(connection.receive(record.copyOfRange(0, 3))).events)
        assertEquals(emptyList(), ok(connection.receive(record.copyOfRange(3, 40))).events)
        val last = ok(connection.receive(record.copyOfRange(40, record.size)))
        assertIs<TlsEvent.ClientHello>(last.events.single())
        assertEquals(TlsState.ProcessingClientHello, connection.state)
    }

    @Test
    fun `change cipher spec batched with client hello is ignored`() {
        val client = TestTlsClient()
        val connection = TlsConnection.create(profile)
        ok(connection.receive(client.clientHelloRecord + TestTlsClient.ccsRecord))
        client.processServerFlight(ok(connection.execute(flight())).outbound)
        assertEquals(TlsState.AwaitClientFinished, connection.state)

        val finished = ok(connection.receive(client.finishedRecord()))
        assertEquals(listOf<TlsEvent>(TlsEvent.ClientFinished), finished.events)
    }

    @Test
    fun `change cipher spec before client finished is ignored`() {
        val client = TestTlsClient()
        val connection = TlsConnection.create(profile)
        afterServerFlight(client, connection)
        val result = ok(connection.receive(TestTlsClient.ccsRecord + client.finishedRecord()))
        assertEquals(listOf<TlsEvent>(TlsEvent.ClientFinished), result.events)
        assertEquals(TlsState.Established, connection.state)
    }

    @Test
    fun `change cipher spec before client hello is rejected`() {
        val connection = TlsConnection.create(profile)
        assertIs<TlsError.Peer.InvalidChangeCipherSpec>(err(connection.receive(TestTlsClient.ccsRecord)))
        assertIs<TlsState.Failed>(connection.state)
    }

    @Test
    fun `repeated change cipher spec within the window is allowed`() {
        val client = TestTlsClient()
        val connection = TlsConnection.create(profile)
        afterServerFlight(client, connection)
        ok(connection.receive(TestTlsClient.ccsRecord + TestTlsClient.ccsRecord))
        assertEquals(TlsState.AwaitClientFinished, connection.state)
    }

    @Test
    fun `change cipher spec after established is rejected`() {
        val (connection, _) = established()
        assertIs<TlsError.Peer.InvalidChangeCipherSpec>(err(connection.receive(TestTlsClient.ccsRecord)))
    }

    @Test
    fun `unsupported cipher suite fails negotiation`() {
        val client = TestTlsClient(0xC02B)
        val connection = TlsConnection.create(profile)
        assertIs<TlsError.Peer.NegotiationFailed>(err(connection.receive(client.clientHelloRecord)))
        assertIs<TlsState.Failed>(connection.state)
    }

    @Test
    fun `wrong client finished fails verification`() {
        val client = TestTlsClient()
        val connection = TlsConnection.create(profile)
        afterServerFlight(client, connection)
        val bogus = client.encryptHandshake(tlsHandshakeMessage(20, ByteArray(client.suite.hashLength)))
        assertEquals(TlsError.Peer.ClientFinishedVerificationFailed, err(connection.receive(bogus)))
    }

    @Test
    fun `ccs while waiting for server flight is ignored`() {
        val client = TestTlsClient()
        val connection = TlsConnection.create(profile)
        ok(connection.receive(client.clientHelloRecord))
        ok(connection.receive(TestTlsClient.ccsRecord))
        assertEquals(TlsState.ProcessingClientHello, connection.state)
    }

    @Test
    fun `handshake data while waiting for server flight is rejected`() {
        val client = TestTlsClient()
        val connection = TlsConnection.create(profile)
        ok(connection.receive(client.clientHelloRecord))
        assertIs<TlsError.Peer.UnexpectedRecord>(err(connection.receive(tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, byteArrayOf(1)))))
        assertIs<TlsState.Failed>(connection.state)
    }

    @Test
    fun `ccs flood is capped`() {
        val client = TestTlsClient()
        val connection = TlsConnection.create(profile)
        ok(connection.receive(client.clientHelloRecord))
        repeat(TLS_MAX_CONSECUTIVE_EMPTY_RECORDS) { ok(connection.receive(TestTlsClient.ccsRecord)) }
        assertIs<TlsError.Peer.TooManyEmptyRecords>(err(connection.receive(TestTlsClient.ccsRecord)))
    }

    @Test
    fun `plaintext alerts are handled`() {
        val close = TlsConnection.create(profile)
        val closeResult = ok(close.receive(tlsRecord(TLS_CONTENT_TYPE_ALERT, byteArrayOf(1, 0))))
        assertEquals(listOf(TlsEvent.ClientCloseNotify), closeResult.events)
        assertContentEquals(tlsRecord(TLS_CONTENT_TYPE_ALERT, byteArrayOf(1, 0)), closeResult.outbound.single())
        assertEquals(TlsState.Closed, close.state)

        val fatal = TlsConnection.create(profile)
        assertEquals(TlsError.Peer.AlertReceived(40), err(fatal.receive(tlsRecord(TLS_CONTENT_TYPE_ALERT, byteArrayOf(2, 40)))))
        assertEquals(null, assertIs<TlsState.Failed>(fatal.state).alert)

        val malformed = TlsConnection.create(profile)
        assertIs<TlsError.Peer.MalformedAlert>(err(malformed.receive(tlsRecord(TLS_CONTENT_TYPE_ALERT, byteArrayOf(1)))))
        val empty = TlsConnection.create(profile)
        assertIs<TlsError.Peer.MalformedAlert>(err(empty.receive(tlsRecord(TLS_CONTENT_TYPE_ALERT, ByteArray(0)))))
    }

    @Test
    fun `close sends a protected close notify after handshake`() {
        val (connection, client) = established()
        val result = ok(connection.execute(TlsCommand.Close))

        assertEquals(TlsState.Closed, connection.state)
        assertContentEquals(byteArrayOf(1, 0), client.decryptAlert(result.outbound.single()))
    }

    @Test
    fun `encrypted client close notify gets a protected server response`() {
        val (connection, client) = established()
        val result = ok(connection.receive(client.encryptAlert(byteArrayOf(1, 0))))

        assertEquals(TlsState.Closed, connection.state)
        assertEquals(listOf(TlsEvent.ClientCloseNotify), result.events)
        assertContentEquals(byteArrayOf(1, 0), client.decryptAlert(result.outbound.single()))
    }

    @Test
    fun `fatal protocol errors return protected TLS alert`() {
        val (connection, client) = established()
        val result = connection.receive(client.encryptHandshake(tlsHandshakeMessage(1, byteArrayOf())))
        assertIs<TlsError.Peer.UnexpectedHandshakeType>(err(result))
        val outbound = assertIs<TlsConnectionResult.Err>(result).outbound

        assertContentEquals(byteArrayOf(2, 10), client.decryptAlert(outbound.single()))
    }

    @Test
    fun `empty handshake record before client hello is rejected`() {
        val connection = TlsConnection.create(profile)
        assertIs<TlsError.Peer.UnexpectedRecord>(err(connection.receive(tlsRecord(TLS_CONTENT_TYPE_HANDSHAKE, ByteArray(0)))))
    }
    @Test
    fun `commands are rejected in the wrong state`() {
        val connection = TlsConnection.create(profile)
        assertIs<TlsError.Usage.InvalidState>(err(connection.execute(flight())))
        assertIs<TlsError.Usage.InvalidState>(err(connection.execute(TlsCommand.SendApplicationData(byteArrayOf(1)))))

        ok(connection.receive(TestTlsClient().clientHelloRecord))
        val empty = TestTlsClient.certificate().copy(certificateChain = emptyList())
        val command = TlsCommand.SendServerFlight(EncryptedExtensionsData(), empty)
        assertIs<TlsError.Usage.InvalidArgument>(err(connection.execute(command)))
        assertEquals(TlsState.ProcessingClientHello, connection.state)
    }

    @Test
    fun `unauthenticated inbound bytes are kept for fallback replay`() {
        val client = TestTlsClient()
        val connection = TlsConnection.create(profile)
        ok(connection.receive(client.clientHelloRecord))
        assertContentEquals(client.clientHelloRecord, connection.unauthenticatedInboundBytes())
        connection.close()
        assertContentEquals(client.clientHelloRecord, connection.unauthenticatedInboundBytes())
    }

    @Test
    fun `unauthenticated bytes survive a failed negotiation`() {
        val client = TestTlsClient(0xC02B)
        val connection = TlsConnection.create(profile)
        err(connection.receive(client.clientHelloRecord))
        assertContentEquals(client.clientHelloRecord, connection.unauthenticatedInboundBytes())
    }

    @Test
    fun `failed and closed connections refuse further use`() {
        val failed = TlsConnection.create(profile)
        val cause = err(failed.receive(TestTlsClient.ccsRecord))
        val usage = assertIs<TlsError.Usage.ConnectionFailed>(err(failed.receive(byteArrayOf(1))))
        assertEquals(cause, usage.cause)

        val closed = TlsConnection.create(profile)
        closed.close()
        assertEquals(TlsError.Usage.ConnectionClosed, err(closed.receive(byteArrayOf(1))))
        assertTrue(ok(closed.execute(TlsCommand.Close)).outbound.isEmpty())
    }
}
