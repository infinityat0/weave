package io.yolabs.libs.weavecommon.tlv

import io.kotlintest.shouldBe
import io.yolabs.libs.weavecommon.WeaveProfileId
import org.junit.jupiter.api.Test

class TLVDecoderTest {

    @Test
    fun `decoder should be able to decode unsigned integer`() {
        parse(0x04, 0x2A) { elem ->
            elem.tag shouldBe AnonymousTag
            elem.value shouldBe UByte(42u)
        }
    }

    @Test
    fun `decoder should be able to parse ContextTag(1)`() {
        parse(0x24, 0x01, 0x2A) { elem ->
            elem.tag shouldBe ContextTag(1u)
            elem.value shouldBe UByte(42u)
        }
    }

    @Test
    fun `decoder should be able to parse core profile tag(1)`() {
        parse(0X44, 0X01, 0X00, 0X2A) { elem ->
            elem.value shouldBe UByte(42u)
            elem.tag shouldBe ProfileTag(profile = WeaveProfileId.Core, value = 1u)
        }
    }

    @Test
    fun `decoder should be able to parse core profile tag(100000)`() {
        parse(0X64, 0XA0, 0X86, 0X01, 0X00, 0X2A) { elem ->
            elem.tag shouldBe ProfileTag(profile = WeaveProfileId.Core, value = 100000u)
            elem.value shouldBe UByte(42u)
        }
    }

    @Test
    fun `decoder should be able to parse fully qualified profile tag`() {
        parse(0XC4, 0XC0, 0X01, 0XC0, 0XDE, 0X01, 0X00, 0X2A) { elem ->
            elem.tag shouldBe ProfileTag(profile = WeaveProfileId(448u, 57024u), value = 1u)
            elem.value shouldBe UByte(42u)
        }
    }

    @Test
    fun `decoder should be able to fully qualified profile tag with large tag value`() {
        parse(0XE4, 0XC0, 0X01, 0XC0, 0XDE, 0X00, 0XFE, 0XED, 0X00, 0X2A) { elem ->
            elem.tag shouldBe ProfileTag(profile = WeaveProfileId(448u, 57024u), value = 15597056u)
            elem.value shouldBe UByte(42u)
        }
    }

    @Test
    fun `decoder should be able to parse structure`() {
        parse(0XD5, 0XC0, 0X01, 0XC0, 0XDE, 0X01, 0X00, 0XC4, 0XC0, 0X01, 0XC0, 0XDE, 0XFE, 0XED, 0X2A, 0X18) { elem ->
            elem.tag shouldBe ProfileTag(profile = WeaveProfileId(448u, 57024u), value = 1u)
            val child = Elem(tag = ProfileTag(WeaveProfileId(448u, 57024u), 60926u), UByte(42u))
            elem.value shouldBe Structure(listOf(child))
        }
    }

    @Test
    fun `decoder should be able to parse structure with implicit tags`() {
        val ints = intArrayOf(0XD5, 0XC0, 0X01, 0XC0, 0XDE, 0X01, 0X00, 0X84, 0XFE, 0XED, 0X2A, 0x18)
        val profileId = WeaveProfileId(448u, 57024u)
        val byteArray = ints.map { it.toByte() }.toByteArray()
        val elem = TLVDecoder.parseBytes(byteArray, profileId)
        elem.tag shouldBe ProfileTag(profile = profileId, value = 1u)
        val child = Elem(tag = ProfileTag(profileId, 60926u), UByte(42u))
        elem.value shouldBe Structure(listOf(child))
    }

    private fun parse(vararg ints: Int, block: (Elem) -> Unit) {
        val byteArray = ints.map { it.toByte() }.toByteArray()
        val elem = TLVDecoder.parseBytes(byteArray)
        block(elem)
    }
}
