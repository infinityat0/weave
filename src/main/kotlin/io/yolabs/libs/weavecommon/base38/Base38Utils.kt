package io.yolabs.libs.weavecommon.base38

import java.nio.ByteBuffer
import java.nio.ByteOrder

@Suppress("MagicNumber")
object Base38Utils {

    private val charset = charArrayOf(
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
        'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '-', '.'
    )
    private val radix = charset.size
    // 3 byte chunks make 5 base 38 chars, 2 byte chunks make 4 base 38 chars and so on.
    private val chunkSizeMap = mapOf(3 to 5, 2 to 4, 1 to 2, 0 to 0)
    // Just an optimization so that we don't do `CharArray(encodeLength) { '0' }.joinToString("")`
    private val padding = arrayOf(
        "",
        "0",
        "00",
        "000",
        "0000",
        "00000"
    )

    /**
     * Returns the size of base38 chars in the end string
     * - Each 3 byte chunk is represented in 5 Base-38 characters,
     * - Final 2 byte chunk is represented in 4 Base-38 characters,
     * - Final 1 byte chunk is represented in 2 Base-38 characters,
     * - + 1 for null termination of the String.
     */
    fun base38Size(array: ByteArray) = (array.size / 3) * 5 + (array.size % 3) * 2 + 1

    /**
     * Converts a given byte array into a Base-38 String.
     */
    fun toBase38(array: ByteArray): String =
        array
            .chunked(n = 3)
            .map { chunk -> toInt(chunk) to chunkSizeMap[chunk.size]!! }
            .joinToString(separator = "") { (int, encodeLength) -> toBase38LE(int, encodeLength) }

    /**
     * Converts each chunk into a 24 bit integer.
     */
    private inline fun toInt(chunk: ByteArray): Int =
        chunk.foldIndexed(initial = 0) { index, sum, byte ->
            sum + ((byte.toInt() and 0xFF) shl (index * 8))
        }

    /**
     * Create a Base 38 representation of the integer and write it out in LITTLE_ENDIAN
     * @param int - the number that needs to be encoded
     * @param encodeLength - expected encoded length
     * @return [int] encoded as a Base-38 String
     */
    private fun toBase38LE(int: Int, encodeLength: Int): String =
        when {
            int == 0 -> padding[encodeLength]
            int > 0  -> charset[int % radix] + toBase38LE(int / radix, encodeLength - 1)
            else     -> error("number is negative: $int")
        }

    /**
     * Create a Base 38 representation of the integer and write it out in BIG_ENDIAN
     * @param int - the number that needs to be encoded
     * @param encodeLength - expected encoded length
     * @return [int] encoded as a Base-38 String
     */
    @Suppress("Unused")
    private fun toBase38BE(int: Int, encodeLength: Int): String =
        when {
            int == 0 -> padding[encodeLength]
            int > 0  -> toBase38BE(int / radix, encodeLength - 1) + charset[int % radix]
            else     -> error("number is negative: $int")
        }
}

/**
 * Only for reference but DO NOT USE THIS METHOD. IT IS SLOW AND MEMORY HOGGING.
 * Present only to illustrate WHAT NOT TO DO and why recursion is not the right answer everytime.
 */
@Suppress("Unused")
fun ByteArray.chunkedRecursive(n: Int): List<ByteArray> =
    when {
        size <= n -> listOf(this)
        else      -> listOf(copyOf(n)) + copyOfRange(n, size).chunkedRecursive(n)
    }

fun ByteArray.chunked(n: Int): List<ByteArray> {
    val list = mutableListOf<ByteArray>()
    for (i in indices step n) {
        list.add(copyOfRange(i, if (i + n > size) size else (i + n)))
    }
    return list
}

fun String.orderedArray(order: ByteOrder = ByteOrder.LITTLE_ENDIAN): ByteArray =
    ByteBuffer.allocate(this.length).order(order).put(toByteArray()).array()

fun Short.orderedArray(order: ByteOrder = ByteOrder.LITTLE_ENDIAN): ByteArray =
    ByteBuffer.allocate(Short.SIZE_BYTES).order(order).putShort(this).array()

fun Int.orderedArray(order: ByteOrder = ByteOrder.LITTLE_ENDIAN): ByteArray =
    ByteBuffer.allocate(Int.SIZE_BYTES).order(order).putInt(this).array()

fun Long.orderedArray(order: ByteOrder = ByteOrder.LITTLE_ENDIAN): ByteArray =
    ByteBuffer.allocate(Long.SIZE_BYTES).order(order).putLong(this).array()
