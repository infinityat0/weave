package io.yolabs.libs.weavecommon.base38

import io.kotlintest.shouldBe
import io.yolabs.libs.weavecommon.toArgs
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

class Base38UtilsTest {

    @ParameterizedTest(name = "Should encode {0} int {1}")
    @MethodSource("getByteArrays")
    fun `should encode byte array to Base-38 string`(byteArray: ByteArray, string: String) {
        Base38Utils.toBase38(array = byteArray) shouldBe string
    }

    @ParameterizedTest(name = "Should encode short {0} to {1} correctly")
    @MethodSource("getShorts")
    fun `should encode short into byte array`(short: Short, byteArray: ByteArray) {
        short.orderedArray().toList() shouldBe byteArray.toList()
    }

    @ParameterizedTest(name = "Should encode int {0} to {1} correctly")
    @MethodSource("getInts")
    fun `should encode int into byte array`(int: Int, byteArray: ByteArray) {
        int.orderedArray().toList() shouldBe byteArray.toList()
    }

    @ParameterizedTest(name = "Should encode long {0} to {1} correctly")
    @MethodSource("getLongs")
    fun `should encode long into byte array`(long: Long, byteArray: ByteArray) {
        long.orderedArray().toList() shouldBe byteArray.toList()
    }

    @ParameterizedTest(name = "Should encode {0} int {1}")
    @MethodSource("getByteArrays")
    fun `should get the correct size of base-38 array`(byteArray: ByteArray, string: String) {
        // +1 because in java we don't terminate Strings with \0. JVM does it for us.
        Base38Utils.base38Size(byteArray) shouldBe (string.length + 1)
    }

    companion object {
        // Test cases from:
        // https://github.com/project-chip/connectedhomeip/blob/master/src/setup_payload/tests/TestQRCode.cpp
        // -1 here being 255.toByte()
        @JvmStatic
        fun getByteArrays() = listOf(
            byteArrayOf()                 to "",
            byteArrayOf(10)               to "A0",
            byteArrayOf(10, 10)           to "OT10",
            byteArrayOf(10, 10, 10)       to "-N.B0",
            byteArrayOf(10, 10, 40)       to "Y6V91",
            byteArrayOf(10, 10, 41)       to "KL0B1",
            byteArrayOf(10, 10, -1)       to "Q-M08",
            byteArrayOf(35)               to "Z0",
            byteArrayOf(-1, 0)            to "R600",
            byteArrayOf(46, 0, 0)         to "81000",
            byteArrayOf(-1)               to "R6",
            byteArrayOf(-1, -1)           to "NE71",
            byteArrayOf(-1, -1, -1)       to "PLS18",
            "Hello World!".orderedArray() to "KKHF3W2S013OPM3EJX11"
        ).map { it.toArgs() }

        @JvmStatic
        fun getShorts() = listOf(
            0x0000.toShort() to byteArrayOf(0x00, 0x00),
            0x000F.toShort() to byteArrayOf(0x0F, 0x00),
            0x0F00.toShort() to byteArrayOf(0x00, 0x0F),
            0xFFFF.toShort() to byteArrayOf(0xFF.b(), 0xFF.b()),
        ).map { it.toArgs() }

        @JvmStatic
        fun getInts() = listOf(
            0x00000000         to byteArrayOf(0x00, 0x00, 0x00, 0x00),
            0x0000000F         to byteArrayOf(0x0F, 0x00, 0x00, 0x00),
            0x000000FF         to byteArrayOf(0xFF.b(), 0x00, 0x00, 0x00),
            0x0000FF00         to byteArrayOf(0x00, 0xFF.b(), 0x00, 0x00),
            0x00FF0000         to byteArrayOf(0x00, 0x00, 0xFF.b(), 0x00),
            0xFF000000.toInt() to byteArrayOf(0x00, 0x00, 0x00, 0xFF.b()),
            0x0000FFFF         to byteArrayOf(0xFF.b(), 0xFF.b(), 0x00, 0x00),
            0xFFFF0000.toInt() to byteArrayOf(0x00, 0x00, 0xFF.b(), 0xFF.b()),
            0xFFFFFFFF.toInt() to byteArrayOf(0xFF.b(), 0xFF.b(), 0xFF.b(), 0xFF.b()),
        ).map { it.toArgs() }

        @JvmStatic
        fun getLongs() = listOf(
            0x00000000 to byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            0x0000000F to byteArrayOf(0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            0x000000FF to byteArrayOf(0xFF.b(), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            0x0000FF00 to byteArrayOf(0x00, 0xFF.b(), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            0x00FF0000 to byteArrayOf(0x00, 0x00, 0xFF.b(), 0x00, 0x00, 0x00, 0x00, 0x00),
            0xFF000000 to byteArrayOf(0x00, 0x00, 0x00, 0xFF.b(), 0x00, 0x00, 0x00, 0x00),
            0x0000FFFF to byteArrayOf(0xFF.b(), 0xFF.b(), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            0xFFFF0000 to byteArrayOf(0x00, 0x00, 0xFF.b(), 0xFF.b(), 0x00, 0x00, 0x00, 0x00),
            0xFFFFFFFF to byteArrayOf(0xFF.b(), 0xFF.b(), 0xFF.b(), 0xFF.b(), 0x00, 0x00, 0x00, 0x00),
        ).map { it.toArgs() }

        private fun Int.b() = this.toByte()
    }
}
