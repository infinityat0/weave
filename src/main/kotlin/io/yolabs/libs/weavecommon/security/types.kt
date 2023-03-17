package io.yolabs.libs.weavecommon.security

import io.yolabs.libs.weavecommon.HEX_RADIX
import io.yolabs.libs.weavecommon.WeaveProfileId
import io.yolabs.libs.weavecommon.security.Asn1Oids.RDN_CHIP_FABRIC_ID
import io.yolabs.libs.weavecommon.security.Asn1Oids.RDN_CHIP_FIRMWARE_SIGNING_ID
import io.yolabs.libs.weavecommon.security.Asn1Oids.RDN_CHIP_ICA_ID
import io.yolabs.libs.weavecommon.security.Asn1Oids.RDN_CHIP_NODE_ID
import io.yolabs.libs.weavecommon.security.Asn1Oids.RDN_CHIP_OP_CERT_AT1
import io.yolabs.libs.weavecommon.security.Asn1Oids.RDN_CHIP_OP_CERT_AT2
import io.yolabs.libs.weavecommon.security.Asn1Oids.RDN_CHIP_ROOT_CA_ID
import io.yolabs.libs.weavecommon.tlv.AnonymousTag
import io.yolabs.libs.weavecommon.tlv.Bool
import io.yolabs.libs.weavecommon.tlv.Bytes
import io.yolabs.libs.weavecommon.tlv.ContextTag
import io.yolabs.libs.weavecommon.tlv.Elem
import io.yolabs.libs.weavecommon.tlv.Str
import io.yolabs.libs.weavecommon.tlv.Structure
import io.yolabs.libs.weavecommon.tlv.TLVDecoder
import io.yolabs.libs.weavecommon.tlv.TLVList
import io.yolabs.libs.weavecommon.tlv.UByte
import io.yolabs.libs.weavecommon.tlv.UInt
import io.yolabs.libs.weavecommon.tlv.ULong
import io.yolabs.libs.weavecommon.tlv.UShort
import io.yolabs.libs.weavecommon.tlv.Value
import io.yolabs.libs.weavecommon.tlv.ValueArray
import io.yolabs.libs.weavecommon.tlv.WrongValueTypeError
import io.yolabs.libs.weavecommon.tlv.hexString
import io.yolabs.libs.weavecommon.tlv.widenToULong
import java.math.BigInteger
import java.nio.ByteBuffer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.KeyPurposeId as BCKeyPurposeId

data class TLVCertificate(
    val serialNum: SerialNumber,
    val signatureAlgo: SignatureAlgo,
    val issuer: Issuer,
    val notBefore: NotBefore,
    val notAfter: NotAfter,
    val subject: Subject,
    val publicKeyAlgo: PublicKeyAlgo,
    val ellipticCurveId: EllipticCurveId,
    val publicKey: PublicKey,
    val extensions: Extensions,
    val signature: SignatureBytes
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
    fun encode(expectedSize: Int = 512): ByteBuffer = Elem(AnonymousTag, toTLV()).encode(expectedSize)
}

data class CertChain(val certs: List<TLVCertificate>) {
    init {
        require(certs.isNotEmpty()) { "CertChain is empty!" }
    }

    fun toTLV() = Elem(AnonymousTag, ValueArray(values = certs.map { it.toTLV() }))

    companion object {
        fun fromBytes(byteArray: ByteArray): CertChain =
            when (val value = TLVDecoder.parseBytes(byteArray).value) {
                is ValueArray -> CertChain(value.values.map { readTLVCert(it) })
                else -> throw WrongValueTypeError(expected = "ValueArray", found = value.javaClass.simpleName)
            }

        private fun readTLVCert(value: Value): TLVCertificate =
            when (value) {
                is Structure -> CertAndKey.readTLVCertFromTLV(value)
                else -> throw WrongValueTypeError(expected = "Structure", found = value.javaClass.simpleName)
            }
    }
}

data class SerialNumber(val serialNum: Bytes)    : Elem(ContextTag(1u), serialNum)
data class SignatureAlgo(val algorithm: UByte)   : Elem(ContextTag(2u), algorithm)
data class Issuer(val list: List<DNAttribute>)   : Elem(ContextTag(3u), TLVList(list.map { it.toElem() }))
data class NotBefore(val time: UInt)             : Elem(ContextTag(4u), time)
data class NotAfter(val time: UInt)              : Elem(ContextTag(5u), time)
data class Subject(val list: List<DNAttribute>)  : Elem(ContextTag(6u), TLVList(list.map { it.toElem() }))
data class PublicKeyAlgo(val algorithm: UByte)   : Elem(ContextTag(7u), algorithm)
data class EllipticCurveId(val curveId: UByte)   : Elem(ContextTag(8u), curveId)
data class PublicKey(val publicKey: Bytes)       : Elem(ContextTag(9u), publicKey)
data class Extensions(val list: List<Extension>) : Elem(ContextTag(10u), TLVList(list.map { it.toElem() }))
data class SignatureBytes(val signature: Bytes)  : Elem(ContextTag(11u), signature)

/**
 * While the spec indicates that this is the structure of the signature, the implementation differs.
 * See: https://github.com/project-chip/connectedhomeip/blob/master/src/credentials/CHIPCert.h
 *
 * Alternatively, use this
 * ```kotlin
 * data class Signature(val signature: Bytes)      : Elem(ContextTag(11u), signature)
 * ```
 */
data class Signature(val r: Bytes, val s: Bytes) : Elem(
    ContextTag(11u),
    Structure(
        listOf(
            Elem(ContextTag(1u), r),
            Elem(ContextTag(2u), s)
        )
    )
)

@Suppress("MagicNumber", "ComplexMethod")
sealed interface DNAttribute {
    val tag: ContextTag
    val value: Value

    fun toElem() = Elem(tag, value)

    data class CommonName(override val value: Str)              : DNAttribute { override val tag = ContextTag(1u) }
    data class Surname(override val value: Str)                 : DNAttribute { override val tag = ContextTag(2u) }
    data class SerialNum(override val value: Str)               : DNAttribute { override val tag = ContextTag(3u) }
    data class CountryName(override val value: Str)             : DNAttribute { override val tag = ContextTag(4u) }
    data class LocalityName(override val value: Str)            : DNAttribute { override val tag = ContextTag(5u) }
    data class StateOrProvinceName(override val value: Str)     : DNAttribute { override val tag = ContextTag(6u) }
    data class OrgName(override val value: Str)                 : DNAttribute { override val tag = ContextTag(7u) }
    data class OrgUnitName(override val value: Str)             : DNAttribute { override val tag = ContextTag(8u) }
    data class Title(override val value: Str)                   : DNAttribute { override val tag = ContextTag(9u) }
    data class Name(override val value: Str)                    : DNAttribute { override val tag = ContextTag(10u) }
    data class GivenName(override val value: Str)               : DNAttribute { override val tag = ContextTag(11u) }
    data class Initials(override val value: Str)                : DNAttribute { override val tag = ContextTag(12u) }
    data class GenQualifier(override val value: Str)            : DNAttribute { override val tag = ContextTag(13u) }
    data class DnQualifier(override val value: Str)             : DNAttribute { override val tag = ContextTag(14u) }
    data class Pseudonym(override val value: Str)               : DNAttribute { override val tag = ContextTag(15u) }
    // Exception case: This class' value is also encoded as a IA5 String
    data class DomainComponent(override val value: Str)         : DNAttribute { override val tag = ContextTag(16u) }
    data class ChipNodeId(override val value: ULong)            : DNAttribute { override val tag = ContextTag(17u) }
    data class ChipFirmwareSigningId(override val value: ULong) : DNAttribute { override val tag = ContextTag(18u) }
    data class ChipIcaId(override val value: ULong)             : DNAttribute { override val tag = ContextTag(19u) }
    data class ChipRootCaId(override val value: ULong)          : DNAttribute { override val tag = ContextTag(20u) }
    data class ChipFabricId(override val value: ULong)          : DNAttribute { override val tag = ContextTag(21u) }
    data class ChipOpCertAt1(override val value: ULong)         : DNAttribute { override val tag = ContextTag(22u) }
    data class ChipOpCertAt2(override val value: ULong)         : DNAttribute { override val tag = ContextTag(23u) }
    // Tags whose values are encoded as IA5 Strings. Context tags are 0x80 OR (corresponding context tag for UTFString)
    data class CommonNamePs(override val value: Str)            : DNAttribute { override val tag = ContextTag(129u) }
    data class SurnamePs(override val value: Str)               : DNAttribute { override val tag = ContextTag(130u) }
    data class SerialNumPs(override val value: Str)             : DNAttribute { override val tag = ContextTag(131u) }
    data class CountryNamePs(override val value: Str)           : DNAttribute { override val tag = ContextTag(132u) }
    data class LocalityNamePs(override val value: Str)          : DNAttribute { override val tag = ContextTag(133u) }
    data class StateOrProvincePamePs(override val value: Str)   : DNAttribute { override val tag = ContextTag(134u) }
    data class OrgNamePs(override val value: Str)               : DNAttribute { override val tag = ContextTag(135u) }
    data class OrgUnitPamePs(override val value: Str)           : DNAttribute { override val tag = ContextTag(136u) }
    data class TitlePs(override val value: Str)                 : DNAttribute { override val tag = ContextTag(137u) }
    data class NamePs(override val value: Str)                  : DNAttribute { override val tag = ContextTag(138u) }
    data class GivenNamePs(override val value: Str)             : DNAttribute { override val tag = ContextTag(139u) }
    data class InitialsPs(override val value: Str)              : DNAttribute { override val tag = ContextTag(140u) }
    data class GenQualifierPs(override val value: Str)          : DNAttribute { override val tag = ContextTag(141u) }
    data class DnQualifierPs(override val value: Str)           : DNAttribute { override val tag = ContextTag(142u) }
    data class PseudonymPs(override val value: Str)             : DNAttribute { override val tag = ContextTag(143u) }

    fun toRDNPair(): Pair<ASN1ObjectIdentifier, String> =
        when (tag.value.toUInt()) {
            1u   -> BCStyle.CN to (value as Str).value
            2u   -> BCStyle.SURNAME to (value as Str).value
            3u   -> BCStyle.SERIALNUMBER to (value as Str).value
            4u   -> BCStyle.C to (value as Str).value
            5u   -> BCStyle.L to (value as Str).value
            6u   -> BCStyle.ST to (value as Str).value
            7u   -> BCStyle.O to (value as Str).value
            8u   -> BCStyle.OU to (value as Str).value
            9u   -> BCStyle.T to (value as Str).value
            10u  -> BCStyle.NAME to (value as Str).value
            11u  -> BCStyle.GIVENNAME to (value as Str).value
            12u  -> BCStyle.INITIALS to (value as Str).value
            13u  -> BCStyle.GENERATION to (value as Str).value
            14u  -> BCStyle.DN_QUALIFIER to (value as Str).value
            15u  -> BCStyle.PSEUDONYM to (value as Str).value
            16u  -> BCStyle.DC to (value as Str).value
            17u  -> Asn1Oids.asASNOid(RDN_CHIP_NODE_ID) to (value as ULong).hexString()
            18u  -> Asn1Oids.asASNOid(RDN_CHIP_FIRMWARE_SIGNING_ID) to (value as ULong).hexString()
            19u  -> Asn1Oids.asASNOid(RDN_CHIP_ICA_ID) to (value as ULong).hexString()
            20u  -> Asn1Oids.asASNOid(RDN_CHIP_ROOT_CA_ID) to (value as ULong).hexString()
            21u  -> Asn1Oids.asASNOid(RDN_CHIP_FABRIC_ID) to (value as ULong).hexString()
            22u  -> Asn1Oids.asASNOid(RDN_CHIP_OP_CERT_AT1) to (value as ULong).hexString()
            23u  -> Asn1Oids.asASNOid(RDN_CHIP_OP_CERT_AT2) to (value as ULong).hexString()
            129u -> BCStyle.CN to (value as Str).value
            130u -> BCStyle.SURNAME to (value as Str).value
            131u -> BCStyle.SERIALNUMBER to (value as Str).value
            132u -> BCStyle.C to (value as Str).value
            133u -> BCStyle.L to (value as Str).value
            134u -> BCStyle.ST to (value as Str).value
            135u -> BCStyle.O to (value as Str).value
            136u -> BCStyle.OU to (value as Str).value
            137u -> BCStyle.T to (value as Str).value
            138u -> BCStyle.NAME to (value as Str).value
            139u -> BCStyle.GIVENNAME to (value as Str).value
            140u -> BCStyle.INITIALS to (value as Str).value
            141u -> BCStyle.GENERATION to (value as Str).value
            142u -> BCStyle.DN_QUALIFIER to (value as Str).value
            143u -> BCStyle.PSEUDONYM to (value as Str).value
            else -> error("Unknown Element: [tag=${tag.value}, value=$value]")
        }

    companion object {
        fun fromOid(oid: ASN1ObjectIdentifier, value: String): DNAttribute =
            when (oid.id) {
                BCStyle.CN.id                -> CommonName(Str(value))
                BCStyle.SURNAME.id           -> Surname(Str(value))
                BCStyle.SERIALNUMBER.id      -> SerialNum(Str(value))
                BCStyle.C.id                 -> CountryName(Str(value))
                BCStyle.L.id                 -> LocalityName(Str(value))
                BCStyle.ST.id                -> StateOrProvinceName(Str(value))
                BCStyle.O.id                 -> OrgName(Str(value))
                BCStyle.OU.id                -> OrgUnitName(Str(value))
                BCStyle.T.id                 -> Title(Str(value))
                BCStyle.NAME.id              -> Name(Str(value))
                BCStyle.GIVENNAME.id         -> GivenName(Str(value))
                BCStyle.INITIALS.id          -> Initials(Str(value))
                BCStyle.GENERATION.id        -> GenQualifier(Str(value))
                BCStyle.DN_QUALIFIER.id      -> DnQualifier(Str(value))
                BCStyle.PSEUDONYM.id         -> Pseudonym(Str(value))
                BCStyle.DC.id                -> DomainComponent(Str(value))
                RDN_CHIP_NODE_ID             -> ChipNodeId(parseULong(value))
                RDN_CHIP_FIRMWARE_SIGNING_ID -> ChipFirmwareSigningId(parseULong(value))
                RDN_CHIP_ICA_ID              -> ChipIcaId(parseULong(value))
                RDN_CHIP_ROOT_CA_ID          -> ChipRootCaId(parseULong(value))
                RDN_CHIP_FABRIC_ID           -> ChipFabricId(parseULong(value))
                RDN_CHIP_OP_CERT_AT1         -> ChipOpCertAt1(parseULong(value))
                RDN_CHIP_OP_CERT_AT2         -> ChipOpCertAt2(parseULong(value))
                else -> error("Unknown OID: $oid")
            }

        fun fromElem(elem: Elem): DNAttribute =
            with(elem) {
                require(tag is ContextTag) { "expected ContextTag while parsing element $elem" }
                when (tag.value.toUInt()) {
                    1u   -> CommonName(value as Str)
                    2u   -> Surname(value as Str)
                    3u   -> SerialNum(value as Str)
                    4u   -> CountryName(value as Str)
                    5u   -> LocalityName(value as Str)
                    6u   -> StateOrProvinceName(value as Str)
                    7u   -> OrgName(value as Str)
                    8u   -> OrgUnitName(value as Str)
                    9u   -> Title(value as Str)
                    10u  -> Name(value as Str)
                    11u  -> GivenName(value as Str)
                    12u  -> Initials(value as Str)
                    13u  -> GenQualifier(value as Str)
                    14u  -> DnQualifier(value as Str)
                    15u  -> Pseudonym(value as Str)
                    16u  -> DomainComponent(value as Str)
                    17u  -> ChipNodeId(value.widenToULong())
                    18u  -> ChipFirmwareSigningId(value.widenToULong())
                    19u  -> ChipIcaId(value as ULong)
                    20u  -> ChipRootCaId(value.widenToULong())
                    21u  -> ChipFabricId(value.widenToULong())
                    22u  -> ChipOpCertAt1(value.widenToULong())
                    23u  -> ChipOpCertAt2(value.widenToULong())
                    129u -> CommonNamePs(value as Str)
                    130u -> SurnamePs(value as Str)
                    131u -> SerialNumPs(value as Str)
                    132u -> CountryNamePs(value as Str)
                    133u -> LocalityNamePs(value as Str)
                    134u -> StateOrProvincePamePs(value as Str)
                    135u -> OrgNamePs(value as Str)
                    136u -> OrgUnitPamePs(value as Str)
                    137u -> TitlePs(value as Str)
                    138u -> NamePs(value as Str)
                    139u -> GivenNamePs(value as Str)
                    140u -> InitialsPs(value as Str)
                    141u -> GenQualifierPs(value as Str)
                    142u -> DnQualifierPs(value as Str)
                    143u -> PseudonymPs(value as Str)
                    else -> error("Unknown Element: [tag=${tag.value}, value=$value]")
                }
            }

        fun parseULong(str: String) = ULong(BigInteger(str, HEX_RADIX).toLong().toULong())
    }
}

@Suppress("MagicNumber", "ComplexMethod")
sealed interface Extension {
    val tag: ContextTag
    val value: Value

    fun toElem() = Elem(tag, value)

    data class BasicConstraints(val isCA: Boolean, val pathLenConstraint: UByte?) : Extension {
        override val tag = ContextTag(1u)

        override val value by lazy {
            val isCAElem = Elem(ContextTag(1u), Bool(isCA))
            val pathLenElem = pathLenConstraint?.let { Elem(ContextTag(2u), it) }
            val elements = pathLenElem?.let { listOf(isCAElem, it) } ?: listOf(isCAElem)
            Structure(elements)
        }

        companion object {
            fun fromElem(elem: Elem): BasicConstraints {
                with(elem) {
                    require(tag == ContextTag(1u)) { "expected ContextTag while parsing element $elem" }
                    require(value is Structure) { "expected Structure while parsing element $elem" }
                    var isCA = false
                    var pathLenConstraint: UByte? = null
                    value.elements.forEach { element ->
                        require(element.tag is ContextTag) { "expected ContextTag while parsing element $elem" }
                        when (element.tag.value.toUInt()) {
                            1u -> isCA = (element.value as Bool).value
                            2u -> pathLenConstraint = (element.value as UByte)
                            else -> error("Unknown Element: [tag=${element.tag}, value=${element.value}]")
                        }
                    }
                    return BasicConstraints(isCA, pathLenConstraint)
                }
            }
        }
    }

    data class KeyUsages(val usages: List<KeyUsage>) : Extension {
        override val tag = ContextTag(2u)
        override val value by lazy {
            // kotlin stdlib is incomplete. It doesn't have a sumOf() function for UShorts
            val result = usages.fold(0u) { acc, usage -> acc + usage.value.value }
            UShort(result.toUShort())
        }

        companion object {
            // DO NOT CHANGE THE ORDER OF THESE VALUES
            val USAGE_LIST = listOf(
                KeyUsage.DIGITAL_SIGNATURE,
                KeyUsage.NON_REPUDIATION,
                KeyUsage.KEY_ENCIPHERMENT,
                KeyUsage.DATA_ENCIPHERMENT,
                KeyUsage.KEY_AGREEMENT,
                KeyUsage.KEY_CERT_SIGN,
                KeyUsage.CRL_SIGN,
                KeyUsage.ENCIPHER_ONLY,
                KeyUsage.DECIPHER_ONLY
            )

            fun fromElem(elem: Elem): KeyUsages =
                with(elem) {
                    require(tag == ContextTag(2u)) { "expected ContextTag(2u) while parsing element $elem" }
                    require(value is UShort || value is UByte) { "expected UShort while parsing element $elem" }

                    val usages = USAGE_LIST.filter { usage ->
                        val usageValue = usage.value.value
                        when (value) {
                            is UShort -> value.value and usageValue > 0u
                            is UByte -> value.value.toUShort() and usageValue > 0u
                            else -> error("Unsupported value type: $value")
                        }
                    }
                    KeyUsages(usages)
                }
        }
    }

    enum class KeyUsage(val value: UShort) {
        DIGITAL_SIGNATURE(UShort(0x0001u)),
        NON_REPUDIATION(UShort(0x0002u)),
        KEY_ENCIPHERMENT(UShort(0x0004u)),
        DATA_ENCIPHERMENT(UShort(0x0008u)),
        KEY_AGREEMENT(UShort(0x0010u)),
        KEY_CERT_SIGN(UShort(0x0020u)),
        CRL_SIGN(UShort(0x0040u)),
        ENCIPHER_ONLY(UShort(0x0080u)),
        DECIPHER_ONLY(UShort(0x0100u));
    }

    data class ExtendedKeyUsage(val keyPurposeIds: List<KeyPurposeId>) : Extension {
        override val tag = ContextTag(3u)
        override val value by lazy { ValueArray(keyPurposeIds.map { it.value }) }

        companion object {
            fun fromElem(elem: Elem): ExtendedKeyUsage =
                with(elem) {
                    require(tag == ContextTag(3u)) { "expected ContextTag while parsing element $elem" }
                    require(value is ValueArray) { "expected ValueArray while parsing element $elem" }
                    val keyPurposeIds = value.values.map { KeyPurposeId.valueOf(it as UByte) }
                    return ExtendedKeyUsage(keyPurposeIds)
                }
        }
    }

    enum class KeyPurposeId(val value: UByte) {
        SERVER_AUTH(UByte(1u)),
        CLIENT_AUTH(UByte(2u)),
        CODE_SIGNING(UByte(3u)),
        EMAIL_PROTECTION(UByte(4u)),
        TIMESTAMPING(UByte(5u)),
        OCSP_SIGNING(UByte(6u));

        companion object {

            fun fromOid(oid: String): KeyPurposeId =
                when (oid) {
                    BCKeyPurposeId.id_kp_serverAuth.id      -> SERVER_AUTH
                    BCKeyPurposeId.id_kp_clientAuth.id      -> CLIENT_AUTH
                    BCKeyPurposeId.id_kp_codeSigning.id     -> CODE_SIGNING
                    BCKeyPurposeId.id_kp_emailProtection.id -> EMAIL_PROTECTION
                    BCKeyPurposeId.id_kp_timeStamping.id    -> TIMESTAMPING
                    BCKeyPurposeId.id_kp_OCSPSigning.id     -> OCSP_SIGNING
                    else -> error("Unknown KeyPurpose ASN1.OID: $oid")
                }

            fun valueOf(id: UByte): KeyPurposeId =
                when (id.value.toUInt()) {
                    1u -> SERVER_AUTH
                    2u -> CLIENT_AUTH
                    3u -> CODE_SIGNING
                    4u -> EMAIL_PROTECTION
                    5u -> TIMESTAMPING
                    6u -> OCSP_SIGNING
                    else -> error("Unknown KeyPurposeId value: $id")
                }
        }
    }

    data class SubjectKeyId(override val value: Bytes)    : Extension { override val tag = ContextTag(4u) }
    data class AuthorityKeyId(override val value: Bytes)  : Extension { override val tag = ContextTag(5u) }
    data class FutureExtension(override val value: Bytes) : Extension { override val tag = ContextTag(6u) }

    companion object {
        fun fromElem(elem: Elem): Extension =
            with(elem) {
                require(tag is ContextTag) { "expected ContextTag while parsing element $elem"  }
                when (tag.value.toUInt()) {
                    1u -> BasicConstraints.fromElem(elem)
                    2u -> KeyUsages.fromElem(elem)
                    3u -> ExtendedKeyUsage.fromElem(elem)
                    4u -> SubjectKeyId(value as Bytes)
                    5u -> AuthorityKeyId(value as Bytes)
                    6u -> FutureExtension(value as Bytes)
                    else -> error("Unknown Extension: [tag=${tag.value}, value=$value]")
                }
            }
    }
}

data class OperationalCSR(
    val csr: Bytes,
    val csrNonce: Bytes,
    val resourceId: Bytes? = null,
    val reserved2: Bytes? = null,
    val reserved3: Bytes? = null
) {
    /**
     * Encodes this TLVCertificate into a bytebuffer
     */
    fun encode(expectedSize: Int = 512): ByteBuffer = Elem(AnonymousTag, toTLV()).encode(expectedSize)

    fun toTLV(): Structure {
        val elements = mutableListOf(
            Elem(ContextTag(1u), csr),
            Elem(ContextTag(2u), csrNonce),
            resourceId?.let { Elem(ContextTag(3u), it) },
            reserved2?.let { Elem(ContextTag(4u), it) },
            reserved3?.let { Elem(ContextTag(5u), it) }
        ).mapNotNull { it }.toList()

        return Structure(elements)
    }

    companion object {

        fun fromBytes(bytes: ByteArray): OperationalCSR =
            fromTLV(TLVDecoder.parseBytes(bytes, WeaveProfileId.Security))

        fun fromTLV(elem: Elem): OperationalCSR {
            val structure = elem.value
            require(structure is Structure) { "expected decoded element value to be a structure: found $structure" }

            var csr: Bytes? = null
            var csrNonce: Bytes? = null
            var resourceId: Bytes? = null
            var reserved2: Bytes? = null
            var reserved3: Bytes? = null
            structure.elements.forEach { elem ->
                with(elem) {
                    require(tag is ContextTag) { "expected ContextTag while parsing element $elem" }
                    when (tag.value.toUInt()) {
                        1u -> csr = value as Bytes
                        2u -> csrNonce = value as Bytes
                        3u -> resourceId = value as Bytes
                        4u -> reserved2 = value as Bytes
                        5u -> reserved3 = value as Bytes
                    }
                }
            }
            require(csr != null && csrNonce != null) { "failed to build OperationalCSR: csr | csrNonce is null" }
            return OperationalCSR(csr!!, csrNonce!!, resourceId, reserved2, reserved3)
        }
    }
}

data class OperationalCSRInfo(val opCSR: OperationalCSR, val signature: Bytes) {
    fun encode(expectedSize: Int = 512): ByteBuffer = Elem(AnonymousTag, toTLV()).encode(expectedSize)

    fun toTLV() = Structure(
        listOf(
            Elem(ContextTag(1u), opCSR.toTLV()),
            Elem(ContextTag(2u), signature)
        )
    )

    companion object {
        fun fromBytes(bytes: ByteArray): OperationalCSRInfo =
            fromTLV(TLVDecoder.parseBytes(bytes, WeaveProfileId.Security))

        private fun fromTLV(elem: Elem): OperationalCSRInfo {
            val structure = elem.value
            require(structure is Structure) { "expected decoded element value to be a structure: found $structure" }

            val elements = structure.elements
            require(elements.size == 2) { "expected 2 elements in the structure. found $elements" }

            return OperationalCSRInfo(
                opCSR = OperationalCSR.fromTLV(elements.first()),
                signature = elements[1].value as Bytes
            )
        }
    }
}
