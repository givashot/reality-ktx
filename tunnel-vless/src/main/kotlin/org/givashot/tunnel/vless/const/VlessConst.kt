package org.givashot.tunnel.vless.const

const val VLESS_VERSION_LENGTH = 1
const val VLESS_UUID_LENGTH = 16

/* addon begin */
const val VLESS_ADD_ON_LENGTH_DESC = 1
const val VLESS_FLOW_NONE = ""
const val VLESS_FLOW_XTLS_RPRX_VISION = "xtls-rprx-vision"
/* addon end */

/* command begin */
const val VLESS_COMMAND_LENGTH = 1
const val VLESS_COMMAND_TYPE_TCP = 1
const val VLESS_COMMAND_TYPE_UDP = 2
const val VLESS_COMMAND_TYPE_MUX = 3
const val VLESS_COMMAND_TYPE_RVS = 4
/* command end */

const val VLESS_PORT_LENGTH = 2

/* address begin */
const val VLESS_ADDRESS_TYPE_LENGTH = 1
const val VLESS_ADDRESS_TYPE_IPV4 = 1
const val VLESS_ADDRESS_TYPE_DOMAIN = 2
const val VLESS_ADDRESS_TYPE_IPV6 = 3
const val VLESS_ADDRESS_TYPE_IPV4_LENGTH = 4
const val VLESS_ADDRESS_TYPE_DOMAIN_LENGTH_DESC = 1
const val VLESS_ADDRESS_TYPE_IPV6_LENGTH = 16
/* address end */