package io.yolabs.libs.weavecommon.tlv

import io.yolabs.libs.weavecommon.WeaveProfileId
import java.nio.ByteBuffer
import java.nio.ByteOrder

object TLVDecoder {
    fun parseBytes(bytes: ByteArray, profile: WeaveProfileId? = null): Elem =
        parse(ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN), profile)

    fun parse(buf: ByteBuffer, profile: WeaveProfileId? = null): Elem =
        decode(buf.order(ByteOrder.LITTLE_ENDIAN), profile)

    @Suppress("MagicNumber", "ComplexMethod", "ThrowsCount")
    private fun decode(buffer: ByteBuffer, profile: WeaveProfileId?): Elem {
        // Unsigned bytes converted to integers do not get their MSB shifted to 31st position
        val control = buffer.uByte()
        val tagBits = (control and TAG_MASK).toInt() ushr 5
        val valueBits = (control and ELEM_MASK).toInt()

        // From the tag bits, parse the tag
        val tag = when (tagBits) {
            0x00 -> AnonymousTag
            0x01 -> ContextTag(buffer.uByte())
            0x02 -> ProfileTag(WeaveProfileId.Core, buffer.uShort().toUInt())
            0x03 -> ProfileTag(WeaveProfileId.Core, buffer.uInt())
            0x04 -> profile?.let { ProfileTag(profile, buffer.uShort().toUInt()) } ?: throw ProfileResolutionError
            0x05 -> profile?.let { ProfileTag(profile, buffer.uInt()) } ?: throw ProfileResolutionError
            0x06 -> ProfileTag(WeaveProfileId(buffer.uShort(), buffer.uShort()), buffer.uShort().toUInt())
            0x07 -> ProfileTag(WeaveProfileId(buffer.uShort(), buffer.uShort()), buffer.uInt())
            else -> throw TagParseError(tagBits) // Reserved
        }

        // From the value bits, find out what type of value it is and it's length
        // TODO (Sunny): Calling [buffer.long.toInt] is wrong. But, I don't think any service instance will
        // have the capability to assign > 2GB of buffer in practice.
        val value = when (valueBits) {
            0x00 -> SByte(buffer.byte())
            0x01 -> SShort(buffer.short)
            0x02 -> SInt(buffer.int)
            0x03 -> SLong(buffer.long)
            0x04 -> UByte(buffer.uByte())
            0x05 -> UShort(buffer.uShort())
            0x06 -> UInt(buffer.uInt())
            0x07 -> ULong(buffer.uLong())
            0x08 -> Bool(false)
            0x09 -> Bool(true)
            0x0A -> Float32(buffer.float)
            0x0B -> Float64(buffer.double)
            0x0C -> readStr(buffer, buffer.byte().asInt())
            0x0D -> readStr(buffer, buffer.short.asInt())
            0x0E -> readStr(buffer, buffer.int) // Wrong: Lengths are unsigned integers
            0x0F -> readStr(buffer, buffer.long.toInt()) // Wrong: See note above
            0x10 -> readBytes(buffer, buffer.byte().asInt())
            0x11 -> readBytes(buffer, buffer.short.asInt())
            0x12 -> readBytes(buffer, buffer.int) // Wrong: Lengths are unsigned integers
            0x13 -> readBytes(buffer, buffer.long.toInt()) // Wrong: See note above
            0x14 -> NULL
            0x15 -> readStructure(buffer, profile)
            0x16 -> readValueArray(buffer, profile)
            0x17 -> readTLVList(buffer, profile)
            0x18 -> throw EndOfContainer
            else -> throw ValueParseError(valueBits)
        }

        return Elem(tag, value)
    }

    private fun readValueArray(buffer: ByteBuffer, profile: WeaveProfileId?): ValueArray {
        val elements = readContainer(buffer, profile)
        require(elements.all { it.tag == AnonymousTag }) { "TLV: Array members should all have Anonymous Tags" }

        return ValueArray(elements.map { it.value })
    }

    private fun readStructure(buffer: ByteBuffer, profile: WeaveProfileId?) = Structure(readContainer(buffer, profile))

    private fun readTLVList(buffer: ByteBuffer, profile: WeaveProfileId?) = TLVList(readContainer(buffer, profile))

    private fun readContainer(buffer: ByteBuffer, profile: WeaveProfileId?): List<Elem> {
        val list = mutableListOf<Elem>()
        try {
            while (true) list.add(decode(buffer, profile))
        } catch (ex: EndOfContainer) { /* This is expected */
        }

        return list.sortedWith(tagComparator)
    }

    private fun readBytes(buffer: ByteBuffer, length: Int): Bytes {
        require(buffer.remaining() >= length) { "TLV: Buffer underflow: Can't parse value into Bytes" }

        val array = ByteArray(length)
        buffer.get(array)
        return Bytes(array)
    }

    private fun readStr(buffer: ByteBuffer, length: Int): Str {
        require(buffer.remaining() >= length) { "TLV: Buffer underflow: Can't parse value into Str" }

        val array = ByteArray(length)
        buffer.get(array)
        return Str(String(array))
    }

    @Suppress("MagicNumber")
    private val TAG_MASK = 0xE0.toUByte()
    private val ELEM_MASK = 0x1F.toUByte()
}
