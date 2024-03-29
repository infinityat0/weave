package io.yolabs.libs.weavecommon.tlv

import io.yolabs.libs.weavecommon.HEX_RADIX
import io.yolabs.libs.weavecommon.tlv.UByte as TLVUByte
import io.yolabs.libs.weavecommon.tlv.UInt as TLVUInt
import io.yolabs.libs.weavecommon.tlv.ULong as TLVULong
import io.yolabs.libs.weavecommon.tlv.UShort as TLVUShort
import java.nio.ByteBuffer

@Suppress("MagicNumber")
fun UInt.isShort(): Boolean = this in 0u..0xFFFFu

fun ByteBuffer.uByte(): UByte = this.get().toUByte()
fun ByteBuffer.uShort(): UShort = this.short.toUShort()
fun ByteBuffer.uInt(): UInt = this.int.toUInt()
fun ByteBuffer.uLong(): ULong = this.long.toULong()

fun ByteBuffer.byte(): Byte = this.get()
fun ByteBuffer.putByte(byte: Byte): ByteBuffer = this.put(byte)

@Suppress("MagicNumber")
fun ByteBuffer.putAndCompress(value: Int): ByteBuffer = when (value) {
    in 0..0xFF -> this.put(value.toByte())
    in 0x100..0xFFFF -> this.putShort(value.toShort())
    else -> this.putInt(value)
}

fun ByteBuffer.putAndCompress(value: UInt): ByteBuffer =
    if (value.isShort()) this.putShort(value.toShort()) else this.putInt(value.toInt())

fun Byte.asInt(): Int = this.toUByte().toInt()
fun Short.asInt(): Int = this.toUShort().toInt()

/**
 * Sort the elements inside the structure with canonical ordering.
 * Return a new structure. Canonical ordering is described in A.2.4 Section of CHIP Spec
 * - Anonymous tags come first
 * - Context tags come after. Context tags with smaller tagId come first
 * - Profile tags are last. Profile tags are ordered based on (vendorId, profileId, tag) in that order
 *
 * https://yolabsio.atlassian.net/browse/SERV-2916?focusedCommentId=33083
 */
val tagComparator = Comparator<Elem> { x, y ->
    when {
        // Anonymous tags come first
        x.tag == AnonymousTag && x.tag == y.tag -> 0
        x.tag == AnonymousTag -> -1
        y.tag == AnonymousTag -> +1
        // Context tags then take precedence
        x.tag is ContextTag && y.tag is ContextTag -> compareValues(x.tag.value, y.tag.value)
        x.tag is ContextTag -> -1
        y.tag is ContextTag -> +1
        // Profile Tags come last
        x.tag is ProfileTag && y.tag is ProfileTag -> {
            val result = compareValues(x.tag.profile.vendorId, y.tag.profile.vendorId)
            if (result == 0) {
                val profileResult = compareValues(x.tag.profile.profileId, y.tag.profile.profileId)
                if (profileResult == 0) compareValues(x.tag.value, y.tag.value) else profileResult
            } else result
        }
        // Should never come here (unless it's an Implicit tag which we resolve anyways)
        else -> throw UnknownTagError
    }
}

fun ULong.hexString(): String = this.toString(HEX_RADIX)
fun UInt.hexString(): String = this.toString(HEX_RADIX)
fun TLVULong.hexString(): String = this.value.toString(HEX_RADIX)

fun Value.widenToULong(): TLVULong = when (this) {
    is TLVUInt   -> TLVULong(value.toULong())
    is TLVUShort -> TLVULong(value.toULong())
    is TLVUByte  -> TLVULong(value.toULong())
    is TLVULong  -> this
    else         -> error("Unsupported value type. Expected UIntN. Found $this")
}
