package io.yolabs.libs.weavecommon.tlv

import io.kotlintest.shouldBe
import io.yolabs.libs.weavecommon.mapFirst
import io.yolabs.libs.weavecommon.toArgs
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

class ExtensionsTest {

    @ParameterizedTest(name = "Byte({0}).asInt() should return {1}")
    @MethodSource("getBytes")
    fun `checking Byte asInt`(byte: Byte, int: Int) {
        byte.asInt() shouldBe int
    }

    @ParameterizedTest(name = "Short({0}).asInt() should return {1}")
    @MethodSource("getShorts")
    fun `checking Short asInt`(short: Short, int: Int) {
        short.asInt() shouldBe int
    }

    @ParameterizedTest(name = "Should compress Int({0}) to {1} bytes")
    @MethodSource("getInts")
    fun `compressing Int to fit into the byte buffer`(int: Int, size: Int) {
        getBuffer().putAndCompress(int).position() shouldBe size
    }

    // Couldn't figure out how to pass UInts as args without making JUnit unhappy
    @Test
    fun `checking UInt can fit in a short`() {
        listOf(
            UInt(0x00u)       to true,
            UInt(0x01u)       to true,
            UInt(0x42u)       to true,
            UInt(0xFFu)       to true,
            UInt(0x100u)      to true,
            UInt(0xFFFFu)     to true,
            UInt(0x10000u)    to false,
            UInt(0x1FFFFu)    to false,
            UInt(0xFFFFFFFFu) to false,
        ).forEach { (value, result) ->
            value.value.isShort() shouldBe result
        }
    }

    @Test
    fun `compressing UInt to fit into the byte buffer`() {
        listOf(
            0x00u       to 2,
            0x01u       to 2,
            0x42u       to 2,
            0xFFu       to 2,
            0x100u      to 2,
            0xFFFFu     to 2,
            0x10000u    to 4,
            0x1FFFFu    to 4,
            0xFFFFFFFFu to 4,
        ).forEach { (value, size) ->
            getBuffer().putAndCompress(value).position() shouldBe size
        }
    }

    companion object {
        private fun getBuffer(): ByteBuffer = ByteBuffer.allocate(10).order(ByteOrder.LITTLE_ENDIAN)

        @JvmStatic
        fun getBytes() = listOf(
            "0"    to 0,
            "1"    to 1,
            "127"  to 127,
            "-128" to 128,
            "-1"   to 255,
        ).map { it.mapFirst { str -> str.toByte() }.toArgs() }

        @JvmStatic
        fun getShorts() = listOf(
            "0"      to 0,
            "1"      to 1,
            "127"    to 127,
            "128"    to 128,
            "32767"  to 32767,
            "-32768" to 32768,
            "-1"     to 65535,
        ).map { it.mapFirst { str -> str.toShort() }.toArgs() }

        @JvmStatic
        fun getInts() = listOf(
            0x00       to 1,
            0x01       to 1,
            0x42       to 1,
            0xFF       to 1,
            0x100      to 2,
            0xFFFF     to 2,
            0x10000    to 4,
            0x1FFFF    to 4,
            0xFFFFFFFF to 4,
        ).map { it.mapFirst { str -> str.toInt() }.toArgs() }
    }
}
