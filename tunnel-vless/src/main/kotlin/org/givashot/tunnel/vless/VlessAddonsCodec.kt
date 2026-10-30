package org.givashot.tunnel.vless

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * Minimal protobuf codec for Xray's `Addons` message (`string Flow = 1; bytes Seed = 2;`), kept dependency-free.
 *
 * Decoding follows proto3 rules: unknown fields are skipped, the last occurrence of a field wins, and the flow must
 * be valid UTF-8. Encoding omits empty fields, so an empty [VlessAddons] encodes to zero bytes.
 */
object VlessAddonsCodec {

    private const val FIELD_FLOW = 1
    private const val FIELD_SEED = 2

    private const val WIRE_VARINT = 0
    private const val WIRE_FIXED64 = 1
    private const val WIRE_LENGTH_DELIMITED = 2
    private const val WIRE_FIXED32 = 5

    private const val MAX_VARINT_BYTES = 10

    /** @throws VlessProtocolException when [bytes] is not a well-formed `Addons` message. */
    fun decode(bytes: ByteArray): VlessAddons {
        if (bytes.isEmpty()) return VlessAddons.EMPTY
        val cursor = Cursor(bytes)
        var flow = ""
        var seed = ByteArray(0)
        while (cursor.hasRemaining()) {
            val tag = cursor.readVarint()
            val fieldNumber = tag ushr 3
            val wireType = (tag and 7).toInt()
            if (fieldNumber == 0L || fieldNumber > Int.MAX_VALUE) {
                throw VlessProtocolException("Invalid VLESS addons field number: $fieldNumber")
            }
            when (fieldNumber.toInt()) {
                FIELD_FLOW -> flow = decodeUtf8(cursor.readLengthDelimited(wireType))
                FIELD_SEED -> seed = cursor.readLengthDelimited(wireType)
                else -> cursor.skip(wireType)
            }
        }
        return VlessAddons(flow, seed)
    }

    fun encode(addons: VlessAddons): ByteArray {
        val out = ByteArrayOutputStream()
        if (addons.flow.isNotEmpty()) writeField(out, FIELD_FLOW, addons.flow.toByteArray(Charsets.UTF_8))
        if (addons.seed.isNotEmpty()) writeField(out, FIELD_SEED, addons.seed)
        return out.toByteArray()
    }

    private fun writeField(out: ByteArrayOutputStream, fieldNumber: Int, value: ByteArray) {
        writeVarint(out, ((fieldNumber shl 3) or WIRE_LENGTH_DELIMITED).toLong())
        writeVarint(out, value.size.toLong())
        out.write(value)
    }

    private fun writeVarint(out: ByteArrayOutputStream, value: Long) {
        var rest = value
        while (rest and 0x7FL.inv() != 0L) {
            out.write(((rest and 0x7F) or 0x80).toInt())
            rest = rest ushr 7
        }
        out.write(rest.toInt())
    }

    private fun decodeUtf8(bytes: ByteArray): String = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: CharacterCodingException) {
        throw VlessProtocolException("VLESS addons flow is not valid UTF-8")
    }

    private class Cursor(private val bytes: ByteArray) {
        private var position = 0

        fun hasRemaining(): Boolean = position < bytes.size

        fun readVarint(): Long {
            var result = 0L
            for (index in 0 until MAX_VARINT_BYTES) {
                if (position >= bytes.size) throw VlessProtocolException("Truncated VLESS addons varint")
                val byte = bytes[position++].toInt()
                result = result or ((byte and 0x7F).toLong() shl (7 * index))
                if (byte and 0x80 == 0) return result
            }
            throw VlessProtocolException("Malformed VLESS addons varint")
        }

        fun readLengthDelimited(wireType: Int): ByteArray {
            if (wireType != WIRE_LENGTH_DELIMITED) {
                throw VlessProtocolException("Unexpected VLESS addons wire type: $wireType")
            }
            val length = readVarint()
            if (length < 0 || length > bytes.size - position) {
                throw VlessProtocolException("Truncated VLESS addons field")
            }
            return bytes.copyOfRange(position, position + length.toInt()).also { position += length.toInt() }
        }

        fun skip(wireType: Int) {
            when (wireType) {
                WIRE_VARINT -> readVarint()
                WIRE_FIXED64 -> skipBytes(8)
                WIRE_LENGTH_DELIMITED -> readLengthDelimited(wireType)
                WIRE_FIXED32 -> skipBytes(4)
                else -> throw VlessProtocolException("Unsupported VLESS addons wire type: $wireType")
            }
        }

        private fun skipBytes(count: Int) {
            if (count > bytes.size - position) throw VlessProtocolException("Truncated VLESS addons field")
            position += count
        }
    }
}
