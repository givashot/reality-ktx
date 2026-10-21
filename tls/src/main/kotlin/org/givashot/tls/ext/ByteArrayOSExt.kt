package org.givashot.tls.ext

import java.io.ByteArrayOutputStream

fun ByteArrayOutputStream.writeUint16(value: Int) {
    write((value ushr 8) and 0xFF)
    write(value and 0xFF)
}

fun ByteArrayOutputStream.writeUint24(value: Int) {
    write((value ushr 16) and 0xFF)
    write((value ushr 8) and 0xFF)
    write(value and 0xFF)
}
