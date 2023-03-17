package io.yolabs.libs.weavecommon.tlv

import io.kotlintest.shouldBe
import io.yolabs.libs.weavecommon.WeaveProfileId
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource

class TagComparatorTest {

    @ParameterizedTest(name = "comparing {0} with {1} should return {2}")
    @MethodSource("tags")
    fun `comparing tags should return the right value`(firstTag: Tag, secondTag: Tag, result: Int) {
        val elem1 = Elem(tag = firstTag, value = UByte(42u))
        val elem2 = Elem(tag = secondTag, value = UByte(42u))
        compare(elem1, elem2) shouldBe result
    }

    companion object {
    private fun compare(elem1: Elem, elem2: Elem): Int =
        compareValuesBy(elem1, elem2, tagComparator) { it }
        @JvmStatic
        fun tags() = listOf(
            Triple(AnonymousTag, AnonymousTag, 0),
            Triple(AnonymousTag, ContextTag(42u), -1),
            Triple(AnonymousTag, ProfileTag(WeaveProfileId.Core, 0u), -1),
            Triple(AnonymousTag, ProfileTag(yoSecurity, 0u), -1),
            Triple(ContextTag(42u), AnonymousTag, 1),
            Triple(ContextTag(0u), ContextTag(42u), -1),
            Triple(ContextTag(42u), ContextTag(42u), 0),
            Triple(ContextTag(42u), ContextTag(0u), 1),
            Triple(ContextTag(42u), ProfileTag(WeaveProfileId.Core, 0u), -1),
            Triple(ContextTag(42u), ProfileTag(yoSecurity, 0u), -1),
            Triple(ProfileTag(yoSecurity, 0u), AnonymousTag, 1),
            Triple(ProfileTag(yoSecurity, 0u), ContextTag(0u), 1),
            Triple(ProfileTag(yoSecurity, 0u), ProfileTag(yoSecurity, 0u), 0),
            // Same vendor, same profile, compare tag values
            Triple(ProfileTag(yoSecurity, 9u), ProfileTag(yoSecurity, 9u), 0),
            Triple(ProfileTag(yoSecurity, 0u), ProfileTag(yoSecurity, 9u), -1),
            Triple(ProfileTag(yoSecurity, 9u), ProfileTag(yoSecurity, 0u), 1),
            // Same Vendor, compare profile values
            Triple(ProfileTag(nestSecurity, 0u), ProfileTag(nestTunnel, 0u), -1),
            Triple(ProfileTag(nestTunnel, 0u), ProfileTag(nestSecurity, 0u), +1),
            // Different vendors, compare vendor values
            Triple(ProfileTag(yoSecurity, 0u), ProfileTag(nestSecurity, 0u), +1),
            Triple(ProfileTag(nestSecurity, 0u), ProfileTag(yoSecurity, 0u), -1),
        ).map { it.toArguments() }
        private val nestSecurity = WeaveProfileId(vendorId = 0x235Au, profileId = 10u)
        private val nestTunnel = WeaveProfileId(vendorId = 0x235Au, profileId = 20u)
        private val yoSecurity = WeaveProfileId(vendorId = 0xFFFFu, profileId = 10u)
        private fun <A, B, C> Triple<A, B, C>.toArguments() = Arguments.of(this.first, this.second, this.third)
    }
}
