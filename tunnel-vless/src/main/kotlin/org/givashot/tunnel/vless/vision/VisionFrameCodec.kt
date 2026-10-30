package org.givashot.tunnel.vless.vision

class VisionFrameCodec(
    uuid: ByteArray,
    private val policy: VisionPaddingPolicy = VisionPaddingPolicy.DEFAULT,
) {

    val serverEncoder by lazy { VisionServerEncoder(uuid, policy) }

    val decoder by lazy { VisionDecoder() }

    fun serverEncode(input: ByteArray): ByteArray {
        return serverEncoder.encode(input)
    }

    fun decode(input: ByteArray): ByteArray {
        return decoder.decode(input)
    }

}
