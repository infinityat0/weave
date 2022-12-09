package io.yolabs.libs.weavecommon.tlv

import io.yolabs.libs.weavecommon.WeaveProfileId
import java.nio.ByteBuffer
import kotlin.UByte
import kotlin.UInt
import kotlin.ULong
import kotlin.UShort

// All types of errors we throw while parsing
object EndOfContainer : Exception() // This is technically not an exception
object UnknownTagError : Exception("TLV: Failed sorting elements. Encountered unknown tag")
object ProfileResolutionError : Exception("TLV: Received Implicit tag but no Implicit profile provided")
class TagParseError(tagValue: Int) : Exception("TLV: Invalid tag type $tagValue")
class ValueParseError(valueType: Int) : Exception("TLV: Invalid value type $valueType")

/**
 * TLV Tags are 4 types:
 *  Anonymous - Usually used to encode elements in an array
 *  Context - Context based tags mapped to a specific profile-id
 *  Implicit - Tags whose profile-id is implied from parent
 *  Profile - Fully qualified Tags with profile Id and tag Id
 */
sealed interface Tag
object AnonymousTag : Tag { override fun toString(): String  = "AnonymousTag" }
@JvmInline value class ContextTag(val value: UByte) : Tag
@JvmInline value class ImplicitTag(val value: UInt) : Tag
data class ProfileTag(val profile: WeaveProfileId, val value: UInt) : Tag

/**
 * TLV Values can be Primitive or Container based
 * Primitive types are - null, Boolean, Signed & Unsigned Numbers, Fractional Numbers, String, Byte[]
 */
sealed interface Value
sealed interface Primitive : Value
object NULL : Primitive
@JvmInline value class Bool(val value: Boolean) : Primitive
@JvmInline value class Str(val value: String) : Primitive
@JvmInline value class Bytes(val value: ByteArray) : Primitive // Prefer this to Array<Byte>

/**
 * Numbers are primitive types. They can be compressed on the wire to shorter values
 */
sealed interface Number : Primitive

sealed interface SignedNumber : Number
@JvmInline value class SByte(val value: Byte) : SignedNumber
@JvmInline value class SShort(val value: Short) : SignedNumber
@JvmInline value class SInt(val value: Int) : SignedNumber
@JvmInline value class SLong(val value: Long) : SignedNumber

sealed interface UnsignedNumber : Number
@JvmInline value class UByte(val value: UByte) : UnsignedNumber
@JvmInline value class UShort(val value: UShort) : UnsignedNumber
@JvmInline value class UInt(val value: UInt) : UnsignedNumber
@JvmInline value class ULong(val value: ULong) : UnsignedNumber

@JvmInline value class Float32(val value: Float) : Number
@JvmInline value class Float64(val value: Double) : Number

/**
 * Container based values are
 * Structures: List of elements
 * Arrays: list of values
 * Paths: ordered list of elements to denote TLV path hierarchies(like URLs)
 */
sealed interface Container : Value
data class Structure(val elements: List<Elem>) : Container
data class ValueArray(val values: List<Value>) : Container
data class TLVList(val elements: List<Elem>) : Container

// TLV Element is contains a tag and a value
open class Elem(val tag: Tag, val value: Value) {
    companion object {
        fun fromBytes(bytes: ByteArray): Elem = TLVDecoder.parseBytes(bytes)

        fun decode(buffer: ByteBuffer): Elem = TLVDecoder.parse(buffer)
    }

    override fun toString(): String = "Elem($tag, $value)"

    override fun equals(that: Any?): Boolean =
        (that != null) && (that is Elem) && (that.tag == tag) && (that.value == value)
    override fun hashCode(): Int = tag.hashCode() + value.hashCode()
    /**
     * Encodes the TLV Element in into a LITTLE_ENDIAN buffer
     */
    fun encode(expectedSize: Int = TLVEncoder.BUF_INITIAL_SIZE): ByteBuffer =
        TLVEncoder.encode(elem = this, size = expectedSize)
}
