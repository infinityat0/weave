package io.yolabs.libs.weavecommon

import java.nio.ByteBuffer
import java.nio.ByteOrder

@SuppressWarnings("MagicNumber")
object TLVEncoder {

    // We should ideally be providing an implicitProfileId to encode but since we always
    // decode implicit tags to their explicit counterparts, we should be fine.
    fun encode(elem: Elem, size: Int = BUF_INITIAL_SIZE): ByteBuffer {
        // Allocate a 4K buffer. If we grow, we will have to copy it but this should suffice for
        // most of TLV things.
        val buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
        return encode(buffer, elem)
    }

    @Suppress("ComplexMethod")
    private fun encode(buffer: ByteBuffer, elem: Elem): ByteBuffer {
        val (tag, value) = elem
        when (value) {
            is SByte      -> { encodeTag(buffer, tag, elemType = 0x00); buffer.putByte(value.value) }
            is SShort     -> { encodeTag(buffer, tag, elemType = 0x01); buffer.putShort(value.value) }
            is SInt       -> { encodeTag(buffer, tag, elemType = 0x02); buffer.putInt(value.value) }
            is SLong      -> { encodeTag(buffer, tag, elemType = 0x03); buffer.putLong(value.value) }
            is UByte      -> { encodeTag(buffer, tag, elemType = 0x04); buffer.putByte(value.value.toByte()) }
            is UShort     -> { encodeTag(buffer, tag, elemType = 0x05); buffer.putShort(value.value.toShort()) }
            is UInt       -> { encodeTag(buffer, tag, elemType = 0x06); buffer.putInt(value.value.toInt()) }
            is ULong      -> { encodeTag(buffer, tag, elemType = 0x07); buffer.putLong(value.value.toLong()) }
            is Bool       -> encodeTag(buffer, tag, elemType = if (!value.value) 0x08 else 0x09)
            is Float32    -> { encodeTag(buffer, tag, elemType = 0x0A); buffer.putFloat(value.value) }
            is Float64    -> { encodeTag(buffer, tag, elemType = 0x0B); buffer.putDouble(value.value) }
            is Str        -> encodeStr(buffer, tag, value)
            is Bytes      -> encodeBytes(buffer, tag, value)
            is NULL       -> encodeTag(buffer, tag, elemType = 0x14)
            is Structure  -> encodeStructure(buffer, tag, value)
            is ValueArray -> encodeValueArray(buffer, tag, value)
            is TLVList    -> encodeTLVList(buffer, tag, value)
        }
        return buffer
    }

    private fun encodeTagControl(buffer: ByteBuffer, tag: Tag, elemType: Int) {
        val tagControl = when (tag) {
            is AnonymousTag -> 0x0
            is ContextTag   -> 0x1
            is ImplicitTag  -> if (tag.value.isShort()) 0x02 else 0x03
            is ProfileTag   -> when (tag.profile) {
                WeaveProfileId.Core -> if (tag.value.isShort()) 0x02 else 0x03
                else                -> if (tag.value.isShort()) 0x06 else 0x07
            }
        }
        // get tag, shift it to MSB 3 bits and add element type 5 bits to it
        val tagControlByte = (((tagControl and 0x07) shl 5) or (elemType and 0x1F)).toByte()
        buffer.putByte(tagControlByte)
    }

    private fun encodeTag(buffer: ByteBuffer, tag: Tag, elemType: Int) {
        // Encode control Octet
        encodeTagControl(buffer, tag, elemType)

        // Now we write the tag
        when (tag) {
            is AnonymousTag -> { } // Nothing to be written here
            is ContextTag   -> buffer.putByte(tag.value.toByte())
            is ImplicitTag  -> buffer.putAndCompress(tag.value)
            is ProfileTag   -> when (tag.profile) {
                WeaveProfileId.Core -> buffer.putAndCompress(tag.value)
                else                -> {
                    buffer.putShort(tag.profile.vendorId.toShort())
                    buffer.putShort(tag.profile.profileId.toShort())
                    buffer.putAndCompress(tag.value)
                }
            }
        }
    }

    private fun encodeStr(buffer: ByteBuffer, tag: Tag, value: Str) {
        val byteArray = value.value.toByteArray(Charsets.UTF_8)
        // encode tag
        when (byteArray.size) {
            in 0..0xFF             -> encodeTag(buffer, tag, elemType = 0x0C)
            in 0x100..0xFFFF       -> encodeTag(buffer, tag, elemType = 0x0D)
            in 0x10000..0xFFFFFFFF -> encodeTag(buffer, tag, elemType = 0x0E)
            else                   -> encodeTag(buffer, tag, elemType = 0x0F)
        }
        // encode length
        buffer.putAndCompress(byteArray.size)
        // encode value
        buffer.put(byteArray)
    }

    @Suppress("NoMultipleSpaces", "MagicNumber")
    private fun encodeBytes(buffer: ByteBuffer, tag: Tag, value: Bytes) {
        val byteArray = value.value
        // encode tag
        when (byteArray.size) {
            in 0..0xFF             -> encodeTag(buffer, tag, elemType = 0x10)
            in 0x100..0xFFFF       -> encodeTag(buffer, tag, elemType = 0x11)
            in 0x10000..0xFFFFFFFF -> encodeTag(buffer, tag, elemType = 0x12)
            else                   -> encodeTag(buffer, tag, elemType = 0x13)
        }
        // Encode length
        buffer.putAndCompress(byteArray.size)
        // encode value
        buffer.put(byteArray)
    }

    private fun encodeStructure(buffer: ByteBuffer, tag: Tag, value: Structure) {
        encodeTag(buffer, tag, elemType = 0x15)
        value.elements.forEach { elem -> encode(buffer, elem) }
        encodeEOC(buffer)
    }

    private fun encodeValueArray(buffer: ByteBuffer, tag: Tag, value: ValueArray) {
        encodeTag(buffer, tag, elemType = 0x16)
        value.values.forEach {
            encode(buffer, Elem(tag = AnonymousTag, value = it))
        }
        encodeEOC(buffer)
    }

    private fun encodeTLVList(buffer: ByteBuffer, tag: Tag, value: TLVList) {
        encodeTag(buffer, tag, elemType = 0x17)
        value.elements.forEach { elem -> encode(buffer, elem) }
        encodeEOC(buffer)
    }

    private fun encodeEOC(buffer: ByteBuffer) = buffer.putByte(0x18)

    // Give it a solid 4K of buffer size. That should suffice for most of our operations!
    private const val BUF_INITIAL_SIZE = 4000
}
