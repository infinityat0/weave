package io.yolabs.libs.weavecommon

import org.junit.jupiter.params.provider.Arguments

fun IntArray.toByteArray() = this.map { it.toByte() }.toByteArray()

fun prettyPrint(array: IntArray) {
    array.toList()
        .chunked(HEX_RADIX)
        .forEach { list ->
            println(list.joinToString(postfix = ",") { "0x%02x".format(it) })
        }
}

fun <A, B> Pair<A, B>.toArgs() = Arguments.of(first, second)
fun <A, B, T> Pair<A, B>.mapFirst(f: (A) -> T): Pair<T, B> = Pair(f(first), second)
fun <A, B, T> Pair<A, B>.mapSecond(f: (B) -> T): Pair<A, T> = Pair(first, f(second))
