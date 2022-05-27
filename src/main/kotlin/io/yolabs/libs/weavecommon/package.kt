package io.yolabs.libs.weavecommon

import java.nio.ByteBuffer

object Namespaces {
    val CORE_NAMESPACE = 0x0000u.toUShort()
    val SECURITY_NAMESPACE = 0x0008u.toUShort()
}

private val hexDumpHeaders =
    """|Offset   | 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
       |----------------------------------------------------------
    """.trimMargin("|")

/**
 * This will pretty print the byte array into a hexdump with the offsets.
 */
fun ByteArray.hexdump(): String {
    val hexdump = this.toList()
        .chunked(16)
        .mapIndexed { index, list ->
            val prefix = "%08x | ".format(index * 16)
            val line = list.joinToString(separator = " ", prefix = prefix) { "%02x".format(it) }
            line
        }
        .joinToString("\n")
    return hexDumpHeaders + "\n" + hexdump
}

/**
 * Hex dumps the buffer contents
 */
fun ByteBuffer.hexdump(): String = this.array().hexdump()