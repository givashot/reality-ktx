package org.givashot.tunnel.vless.const

const val VISION_COMMAND_PADDING_CONTINUE = 0

/**
 * Vision command padding end, normally means the dest and client not over tls 1.3 or with TLS_AES_128_CCM_8_SHA256 cipher suites,
 * we should protect the connection over TLS 1.3 between client and server
 */
const val VISION_COMMAND_PADDING_END = 1
const val VISION_COMMAND_PADDING_DIRECT = 2

/** command (1) | content length (2) | padding length (2). */
const val VISION_FRAME_HEADER_LENGTH = 5

/**
 * Max padding handshake tls record count server side
 * HRR + SH + CCS + EE + CR + Certificate + CV + FINISHED
 */
const val VISION_MAX_PADDING_COUNT_OVER_TLS_SERVER_SIDE = 8

const val VISION_MAX_PADDING_COUNT_NON_TLS_SERVER_SIDE = 8

