package io.yolabs.libs.weavecommon.verhoeff

import io.kotlintest.shouldBe
import kotlin.random.Random
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

class VerhoeffTest {
    @ParameterizedTest(name = "Should generate Verhoeff of {0} and validate it")
    @MethodSource("getInts")
    fun `should generate and validate Verhoeff digit`(input: String) {
        val digit = Verhoeff.generate(input).toString()
        Verhoeff.validate(input + digit) shouldBe true
    }

    companion object {

        @JvmStatic
        fun getInts() = (1..10).map {
            Random.nextInt(0, 10000000).toString()
        }
    }
}
