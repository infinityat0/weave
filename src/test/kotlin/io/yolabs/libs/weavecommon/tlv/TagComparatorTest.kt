package io.yolabs.libs.weavecommon.tlv

import io.kotlintest.shouldBe
import org.junit.jupiter.api.Test

class TagComparatorTest {

    @Test
    fun `(anonymous, anonymous) should order anonymous tags first`() {
        val elem1 = Elem(tag = AnonymousTag, value = UByte(42u))
        val elem2 = Elem(tag = AnonymousTag, value = UByte(21u))
        compare(elem1, elem2) shouldBe 0
    }

    private fun compare(elem1: Elem, elem2: Elem): Int =
        compareValuesBy(elem1, elem2, tagComparator) { it }
}
