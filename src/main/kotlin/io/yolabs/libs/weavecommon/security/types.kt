package io.yolabs.libs.weavecommon.security

import io.yolabs.libs.weavecommon.tlv.Bool
import io.yolabs.libs.weavecommon.tlv.Bytes
import io.yolabs.libs.weavecommon.tlv.ContextTag
import io.yolabs.libs.weavecommon.tlv.Elem
import io.yolabs.libs.weavecommon.tlv.Str
import io.yolabs.libs.weavecommon.tlv.Structure
import io.yolabs.libs.weavecommon.tlv.TLVList
import io.yolabs.libs.weavecommon.tlv.Tag
import io.yolabs.libs.weavecommon.tlv.UByte
import io.yolabs.libs.weavecommon.tlv.UInt
import io.yolabs.libs.weavecommon.tlv.ULong
import io.yolabs.libs.weavecommon.tlv.UShort
import io.yolabs.libs.weavecommon.tlv.Value
import io.yolabs.libs.weavecommon.tlv.ValueArray

data class TLVCertificate(
    private val serialNum: SerialNumber,
    private val signatureAlgo: SignatureAlgo,
    private val issuer: Issuer,
    private val notBefore: NotBefore,
    private val notAfter: NotAfter,
    private val subject: Subject,
    private val publicKeyAlgo: PublicKeyAlgo,
    private val ellipticCurveId: EllipticCurveId,
    private val publicKey: PublicKey,
    private val extensions: Extensions,
    private val signature: Signature
) {
    /**
     * Returns a TLV representation of this certificate
     */
    fun toTLV() = Structure(
        listOf(
            serialNum,
            signatureAlgo,
            issuer,
            notBefore,
            notAfter,
            subject,
            publicKeyAlgo,
            ellipticCurveId,
            publicKey,
            extensions,
            signature
        )
    )

    /**
     * Encodes this TLVCertificate into a bytebuffer
     */
    // fun encode(): ByteBuffer = toTLV().encode()
}

data class SerialNumber(private val serialNum: Bytes)   : Elem(ContextTag(1u), serialNum)
data class SignatureAlgo(private val algorithm: UByte)  : Elem(ContextTag(2u), algorithm)
data class Issuer(private val list: List<DNAttribute>)  : Elem(ContextTag(3u), TLVList(list.map { it.toElem()}))
data class NotBefore(private val time: UInt)            : Elem(ContextTag(4u), time)
data class NotAfter(private val time: UInt)             : Elem(ContextTag(5u), time)
data class Subject(private val list: List<DNAttribute>) : Elem(ContextTag(6u), TLVList(list.map { it.toElem()}))
data class PublicKeyAlgo(private val algorithm: UByte)  : Elem(ContextTag(7u), algorithm)
data class EllipticCurveId(private val curveId: UByte)  : Elem(ContextTag(8u), curveId)
data class PublicKey(private val publicKey: Bytes)      : Elem(ContextTag(9u), publicKey)
data class Extensions(private val list: List<Extension>): Elem(ContextTag(10u), TLVList(list.map { it.toElem()}))
data class Signature(private val r: String, private val s: String) : Elem(
    ContextTag(11u), Structure(
        listOf(
            Elem(ContextTag(1u), Str(r)),
            Elem(ContextTag(2u), Str(s))
        )
    )
)

sealed interface DNAttribute {
    val tag: Tag
    val value: Value

    fun toElem() = Elem(tag, value)

    class CommonName(override val value: Str)              : DNAttribute { override val tag = ContextTag(1u) }
    class Surname(override val value : Str)                : DNAttribute { override val tag = ContextTag(2u) }
    class SerialNum(override val value : Str)              : DNAttribute { override val tag = ContextTag(3u) }
    class CountryName(override val value : Str)            : DNAttribute { override val tag = ContextTag(4u) }
    class LocalityName(override val value : Str)           : DNAttribute { override val tag = ContextTag(5u) }
    class StateOrProvinceName(override val value : Str)    : DNAttribute { override val tag = ContextTag(6u) }
    class OrgName(override val value : Str)                : DNAttribute { override val tag = ContextTag(7u) }
    class OrgUnitName(override val value : Str)            : DNAttribute { override val tag = ContextTag(8u) }
    class Title(override val value : Str)                  : DNAttribute { override val tag = ContextTag(9u) }
    class Name(override val value : Str)                   : DNAttribute { override val tag = ContextTag(10u) }
    class GivenName(override val value : Str)              : DNAttribute { override val tag = ContextTag(11u) }
    class Initials(override val value : Str)               : DNAttribute { override val tag = ContextTag(12u) }
    class GenQualifier(override val value : Str)           : DNAttribute { override val tag = ContextTag(13u) }
    class DnQualifier(override val value : Str)            : DNAttribute { override val tag = ContextTag(14u) }
    class Pseudonym(override val value : Str)              : DNAttribute { override val tag = ContextTag(15u) }
    // Exception case: This class' value is also encoded as a IA5 String
    class DomainComponent(override val value : Str)        : DNAttribute { override val tag = ContextTag(16u) }
    class ChipNodeId(override val value : ULong)           : DNAttribute { override val tag = ContextTag(17u) }
    class ChipFirmwareSigningId(override val value : ULong): DNAttribute { override val tag = ContextTag(18u) }
    class ChipIcaId(override val value : ULong)            : DNAttribute { override val tag = ContextTag(19u) }
    class ChipRootCaId(override val value : ULong)         : DNAttribute { override val tag = ContextTag(20u) }
    class ChipFabricId(override val value : ULong)         : DNAttribute { override val tag = ContextTag(21u) }
    class ChipOpcertAt1(override val value : ULong)        : DNAttribute { override val tag = ContextTag(22u) }
    class ChipOpcertAt2(override val value : ULong)        : DNAttribute { override val tag = ContextTag(23u) }
    // Tags whose values are encoded as IA5 Strings. Context tags are 0x80 OR (corresponding context tag for UTFString)
    class CommonNamePs(override val value: Str)            : DNAttribute { override val tag = ContextTag(129u) }
    class SurnamePs(override val value: Str)               : DNAttribute { override val tag = ContextTag(130u) }
    class SerialNumPs(override val value: Str)             : DNAttribute { override val tag = ContextTag(131u) }
    class CountryNamePs(override val value: Str)           : DNAttribute { override val tag = ContextTag(132u) }
    class LocalityNamePs(override val value: Str)          : DNAttribute { override val tag = ContextTag(133u) }
    class StateOrProvincePamePs(override val value: Str)   : DNAttribute { override val tag = ContextTag(134u) }
    class OrgNamePs(override val value: Str)               : DNAttribute { override val tag = ContextTag(135u) }
    class OrgUnitPamePs(override val value: Str)           : DNAttribute { override val tag = ContextTag(136u) }
    class TitlePs(override val value: Str)                 : DNAttribute { override val tag = ContextTag(137u) }
    class NamePs(override val value: Str)                  : DNAttribute { override val tag = ContextTag(138u) }
    class GivenNamePs(override val value: Str)             : DNAttribute { override val tag = ContextTag(139u) }
    class InitialsPs(override val value: Str)              : DNAttribute { override val tag = ContextTag(140u) }
    class GenQualifierPs(override val value: Str)          : DNAttribute { override val tag = ContextTag(141u) }
    class DnQualifierPs(override val value: Str)           : DNAttribute { override val tag = ContextTag(142u) }
    class PseudonymPs(override val value: Str)             : DNAttribute { override val tag = ContextTag(143u) }
}

sealed interface Extension {
    val tag: Tag
    val value: Value

    fun toElem() = Elem(tag, value)


    class BasicCnstr(isCA: Boolean, pathLenConstraint: UByte?) : Extension {
        override val tag = ContextTag(1u)

        override val value by lazy {
            val isCAElem = Elem(ContextTag(1u), Bool(isCA))
            val pathLenElem = pathLenConstraint?.let { Elem(ContextTag(2u), it) }
            val elements = pathLenElem?.let { listOf(isCAElem, it) } ?: listOf(isCAElem)
            Structure(elements)
        }
    }
    class KeyUsages(private val usage: KeyUsage) : Extension {
        override val tag = ContextTag(2u)
        override val value by lazy { usage.value }
    }
    class ExtendedKeyUsage(private val usages: List<KeyPurposeId>) : Extension {
        override val tag = ContextTag(3u)
        override val value by lazy { ValueArray(usages.map { it.value }) }
    }
    class SubjectKeyId(override val value: Bytes)   : Extension { override val tag = ContextTag(4u) }
    class AuthorityKeyId(override val value: Bytes) : Extension { override val tag = ContextTag(5u) }
    class FutureExtension(override val value: Bytes): Extension { override val tag = ContextTag(6u) }

    enum class KeyUsage(val value: UShort) {
        DIGITAL_SIGNATURE(UShort(0x0001u)),
        NON_REPUDIATION(UShort(0x0002u)),
        KEY_ENCIPHERMENT(UShort(0x0004u)),
        DATA_ENCIPHERMENT(UShort(0x0008u)),
        KEY_AGREEMENT(UShort(0x0010u)),
        KEY_CERTSIGN(UShort(0x0020u)),
        CRL_SIGN(UShort(0x0040u)),
        ENCIPHER_ONLY(UShort(0x0080u)),
        DECIPHER_ONLY(UShort(0x0100u)),
    }

    enum class KeyPurposeId(val value: UByte) {
        SERVER_AUTH(UByte(1u)),
        CLIENT_AUTH(UByte(2u)),
        CODE_SIGNING(UByte(3u)),
        EMAIL_PROTECTION(UByte(4u)),
        TIMESTAMPING(UByte(5u)),
        OCSP_SIGNING(UByte(6u))
    }
}
