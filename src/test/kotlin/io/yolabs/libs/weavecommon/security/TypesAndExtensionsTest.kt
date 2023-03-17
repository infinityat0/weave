package io.yolabs.libs.weavecommon.security

import io.kotlintest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotlintest.shouldBe
import io.yolabs.libs.weavecommon.WeaveProfileId
import io.yolabs.libs.weavecommon.security.DNAttribute.ChipFabricId
import io.yolabs.libs.weavecommon.security.DNAttribute.ChipFirmwareSigningId
import io.yolabs.libs.weavecommon.security.DNAttribute.ChipIcaId
import io.yolabs.libs.weavecommon.security.DNAttribute.ChipNodeId
import io.yolabs.libs.weavecommon.security.DNAttribute.ChipOpCertAt1
import io.yolabs.libs.weavecommon.security.DNAttribute.ChipOpCertAt2
import io.yolabs.libs.weavecommon.security.DNAttribute.ChipRootCaId
import io.yolabs.libs.weavecommon.security.DNAttribute.CommonName
import io.yolabs.libs.weavecommon.security.DNAttribute.CommonNamePs
import io.yolabs.libs.weavecommon.security.DNAttribute.CountryName
import io.yolabs.libs.weavecommon.security.DNAttribute.CountryNamePs
import io.yolabs.libs.weavecommon.security.DNAttribute.DnQualifier
import io.yolabs.libs.weavecommon.security.DNAttribute.DnQualifierPs
import io.yolabs.libs.weavecommon.security.DNAttribute.DomainComponent
import io.yolabs.libs.weavecommon.security.DNAttribute.GenQualifier
import io.yolabs.libs.weavecommon.security.DNAttribute.GenQualifierPs
import io.yolabs.libs.weavecommon.security.DNAttribute.GivenName
import io.yolabs.libs.weavecommon.security.DNAttribute.GivenNamePs
import io.yolabs.libs.weavecommon.security.DNAttribute.Initials
import io.yolabs.libs.weavecommon.security.DNAttribute.InitialsPs
import io.yolabs.libs.weavecommon.security.DNAttribute.LocalityName
import io.yolabs.libs.weavecommon.security.DNAttribute.LocalityNamePs
import io.yolabs.libs.weavecommon.security.DNAttribute.Name
import io.yolabs.libs.weavecommon.security.DNAttribute.NamePs
import io.yolabs.libs.weavecommon.security.DNAttribute.OrgName
import io.yolabs.libs.weavecommon.security.DNAttribute.OrgNamePs
import io.yolabs.libs.weavecommon.security.DNAttribute.OrgUnitName
import io.yolabs.libs.weavecommon.security.DNAttribute.OrgUnitPamePs
import io.yolabs.libs.weavecommon.security.DNAttribute.Pseudonym
import io.yolabs.libs.weavecommon.security.DNAttribute.PseudonymPs
import io.yolabs.libs.weavecommon.security.DNAttribute.SerialNum
import io.yolabs.libs.weavecommon.security.DNAttribute.SerialNumPs
import io.yolabs.libs.weavecommon.security.DNAttribute.StateOrProvinceName
import io.yolabs.libs.weavecommon.security.DNAttribute.StateOrProvincePamePs
import io.yolabs.libs.weavecommon.security.DNAttribute.Surname
import io.yolabs.libs.weavecommon.security.DNAttribute.SurnamePs
import io.yolabs.libs.weavecommon.security.DNAttribute.Title
import io.yolabs.libs.weavecommon.security.DNAttribute.TitlePs
import io.yolabs.libs.weavecommon.security.Extension.AuthorityKeyId
import io.yolabs.libs.weavecommon.security.Extension.BasicConstraints
import io.yolabs.libs.weavecommon.security.Extension.ExtendedKeyUsage
import io.yolabs.libs.weavecommon.security.Extension.FutureExtension
import io.yolabs.libs.weavecommon.security.Extension.KeyPurposeId
import io.yolabs.libs.weavecommon.security.Extension.KeyUsage
import io.yolabs.libs.weavecommon.security.Extension.KeyUsages
import io.yolabs.libs.weavecommon.security.Extension.SubjectKeyId
import io.yolabs.libs.weavecommon.tlv.Bytes
import io.yolabs.libs.weavecommon.tlv.ContextTag
import io.yolabs.libs.weavecommon.tlv.Elem
import io.yolabs.libs.weavecommon.tlv.Str
import io.yolabs.libs.weavecommon.tlv.Structure
import io.yolabs.libs.weavecommon.tlv.TLVDecoder
import io.yolabs.libs.weavecommon.tlv.UByte as TLVUByte
import io.yolabs.libs.weavecommon.tlv.UShort as TLVUShort
import io.yolabs.libs.weavecommon.tlv.Value
import io.yolabs.libs.weavecommon.toArgs
import kotlin.random.Random
import kotlin.to
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.KeyPurposeId as BCKeyPurposeId
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

class TypesAndExtensionsTest {

    @ParameterizedTest(name = "Should convert {0} to ASNOid {1}")
    @MethodSource("getASNOids")
    fun `should convert to ASN1ObjectIdentifier correctly`(oidStr: String, asnId: ASN1ObjectIdentifier) {
        asnId shouldBe Asn1Oids.asASNOid(oidStr)
    }

    @Test
    fun `should dencode operational CSR to object and back`() {
        val opCSR = makeOpCSR(includeFutureFields = true)
        val encoded = opCSR.encode()
        val decoded = OperationalCSR.fromBytes(encoded.array())
        opCSR shouldBeSimilarTo decoded
    }

    @Test
    fun `should dencode operation CSR to object when optional fields are null`() {
        val opCSR = OperationalCSR(
            csr = Bytes(Random.nextBytes(100)),
            csrNonce = Bytes(Random.nextBytes(16))
        )
        val encoded = opCSR.encode()
        val decoded = OperationalCSR.fromBytes(encoded.array())
        opCSR shouldBeSimilarTo decoded
    }

    @Test
    fun `should dencode operational CSR info object and back`() {
        val opCSRInfo = makeOpCSRInfo()
        val encoded = opCSRInfo.encode()
        val decoded = OperationalCSRInfo.fromBytes(encoded.array())
        opCSRInfo shouldBeSimilarTo decoded
    }

    @Test
    fun `should dencode certificate simpler correctly`() {
        val extensions = listOf(
            SubjectKeyId(Bytes(nextBytes(32))),
            AuthorityKeyId(Bytes(nextBytes(32))),
            FutureExtension(Bytes(nextBytes(32)))
        )

        extensions.forEach { extension ->
            val dencoded = Extension.fromElem(extension.toElem())
            dencoded.tag shouldBe extension.tag
            (dencoded.value as Bytes).value.contentEquals((extension.value as Bytes).value)
        }
    }

    @Test
    fun `should fail decoding when the tag is not an extension`() {
        val elem = Elem(ContextTag(10u), Bytes(nextBytes(32)))
        assertThrows<IllegalStateException> { Extension.fromElem(elem) }
    }

    @Test
    fun `should dencode ExtendedKeyUsage correctly`() {
        val extendedKeyUsage = ExtendedKeyUsage(KeyPurposeId.values().toList())
        val dencoded = Extension.fromElem(extendedKeyUsage.toElem()) as ExtendedKeyUsage
        dencoded.tag shouldBe extendedKeyUsage.tag
        dencoded.keyPurposeIds shouldBe extendedKeyUsage.keyPurposeIds
    }

    @ParameterizedTest(name = "Should convert {0} to KeyPurposeId {1}")
    @MethodSource("getKeyPurposeIds")
    fun `should be able to map KeyPurposeId to ASN1ObjectIdentifier`(
        asnId: BCKeyPurposeId,
        keyPurposeId: KeyPurposeId
    ) {
        KeyPurposeId.fromOid(asnId.id) shouldBe keyPurposeId
    }

    @Test
    fun `should fail decoding when the tag is an unsupported KeyPurposeId`() {
        assertThrows<IllegalStateException> { KeyPurposeId.fromOid(BCKeyPurposeId.id_kp_scvpServer.id) }
    }

    @ParameterizedTest(name = "Should convert tlv value[{0}] to KeyPurposeId {1}")
    @MethodSource("getTLVKeyPurposeIds")
    fun `should be able to convert tlv to keyPurposeId`(value: Int, keyPurposeId: KeyPurposeId) {
        KeyPurposeId.valueOf(TLVUByte(value.toUByte())) shouldBe keyPurposeId
    }

    @Test
    fun `should fail to map an unknown value to keyPurposeId`() {
        assertThrows<IllegalStateException> { KeyPurposeId.valueOf(TLVUByte(20u)) }
    }

    @Test
    fun `should map the correct key usages`() {
        val usages = KeyUsages(KeyUsages.USAGE_LIST)
        val dencoded = KeyUsages.fromElem(usages.toElem())
        dencoded.tag shouldBe usages.tag
        dencoded.usages shouldBe usages.usages
    }

    @Test
    fun `should be able to correctly decode a key usage`() {
        // Regardless of value encoding, we should parse KeyUsage TLV
        val elements = listOf(
            Elem(ContextTag(2u), TLVUByte(5u)),
            Elem(ContextTag(2u), TLVUShort(5u))
        )
        elements.forEach { element ->
            val parsed = KeyUsages.fromElem(element)
            parsed.tag shouldBe element.tag
            parsed.usages shouldContainExactlyInAnyOrder listOf(KeyUsage.KEY_ENCIPHERMENT, KeyUsage.DIGITAL_SIGNATURE)
        }
    }

    @Test
    fun `should parse BasicConstraints correctly from TLV`() {
        listOf(
            BasicConstraints(isCA = true, pathLenConstraint = null),
            BasicConstraints(isCA = true, pathLenConstraint = TLVUByte(1u)),
            BasicConstraints(isCA = false, pathLenConstraint = null),
            BasicConstraints(isCA = false, pathLenConstraint = TLVUByte(1u)),
        ).forEach { basicConstraints ->
            val parsed = Elem.fromBytes(basicConstraints.toElem().encode().array())
            val dencoded = BasicConstraints.fromElem(parsed)
            dencoded shouldBe basicConstraints
        }
    }

    @ParameterizedTest(name = "Should convert AsnOID {0} to DNAttribute {1}")
    @MethodSource("getDNAttributeOids")
    fun `should be able to map DNAttribute to from value`(asnOId: ASN1ObjectIdentifier, dnAttribute: DNAttribute) {
        DNAttribute.fromOid(asnOId, DN_ATTRIBUTE_VALUE) shouldBe dnAttribute
    }

    @Test
    fun `should fail mapping an unknown dnAttribute`() {
        assertThrows<IllegalStateException> { DNAttribute.fromOid(BCStyle.UID, "42") }
    }

    @ParameterizedTest(name = "Should extract RDN pair as {0} for a given DNAttribute {1}")
    @MethodSource("getDNAttributeOids")
    fun `should be able to extract RDN pair`(asnOId: ASN1ObjectIdentifier, dnAttribute: DNAttribute) {
        dnAttribute.toRDNPair().first shouldBe asnOId
    }

    @Test
    fun `should be able to extract RDN pair for IA5 String tag elements`() {
        listOf(
            BCStyle.CN to CommonNamePs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.SURNAME to SurnamePs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.SERIALNUMBER to SerialNumPs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.C to CountryNamePs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.L to LocalityNamePs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.ST to StateOrProvincePamePs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.O to OrgNamePs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.OU to OrgUnitPamePs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.T to TitlePs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.NAME to NamePs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.GIVENNAME to GivenNamePs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.INITIALS to InitialsPs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.GENERATION to GenQualifierPs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.DN_QUALIFIER to DnQualifierPs(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.PSEUDONYM to PseudonymPs(Str(DN_ATTRIBUTE_VALUE))
        ).forEach { (asnOid, dnAttribute) ->
            with(dnAttribute.toRDNPair()) {
                first shouldBe asnOid
                second shouldBe DN_ATTRIBUTE_VALUE
            }
        }
    }

    @ParameterizedTest(name = "Should extract DNAttribute from an {0}")
    @MethodSource("getDNAttributeElements")
    fun `should be able to extract DNAttribute from an Elem`(elem: Elem, dnAttribute: DNAttribute) {
        DNAttribute.fromElem(elem) shouldBe dnAttribute
    }

    @Test
    fun `should fail extracting DNAttribute from a malformed Elem`() {
        assertThrows<IllegalStateException> {
            DNAttribute.fromElem(Elem(ContextTag(200u), Bytes(nextBytes(32))))
        }
    }

    @Test
    fun `should dencode Signature correctly`() {
        val signature = Signature(r = Bytes(nextBytes(32)), s = Bytes(nextBytes(32)))
        val dencoded = TLVDecoder.parseBytes(signature.encode().array(), WeaveProfileId.Security)

        with(dencoded) {
            val structure = value as Structure
            with(structure) {
                elements.size shouldBe 2
                (elements[0].value as Bytes) shouldBeSimilarTo signature.r
                (elements[1].value as Bytes) shouldBeSimilarTo signature.s
            }
        }
    }
    companion object {

        infix fun Bytes.shouldBeSimilarTo(that: Value) {
            (that is Bytes) shouldBe true
            this.value.contentEquals((that as Bytes).value) shouldBe true
        }

        private fun makeOpCSR(
            nonce: ByteArray = nextBytes(16),
            resourceId: String = "resource-id-${nextNumber()}",
            includeFutureFields: Boolean = false
        ) = OperationalCSR(
            csr = Bytes(nextBytes(100)),
            csrNonce = Bytes(nonce),
            resourceId = Bytes(resourceId.toByteArray()),
            reserved2 = if (includeFutureFields) Bytes(dummyByteArray) else null,
            reserved3 = if (includeFutureFields) Bytes(dummyByteArray) else null,
        )

        private fun makeOpCSRInfo(
            opCSR: OperationalCSR = makeOpCSR(),
            signature: ByteArray = nextBytes(128)
        ) = OperationalCSRInfo(opCSR = opCSR, signature = Bytes(signature))

        /**
         * Compares two OperationalCSR datatypes. This is not perfect but will do.
         */
        infix fun OperationalCSR.shouldBeSimilarTo(that: OperationalCSR) {
            this.csr.value  contentEquals that.csr.value shouldBe true
            this.csrNonce.value contentEquals that.csrNonce.value shouldBe true
            this.resourceId?.let { it.value.contentEquals(that.resourceId?.value) shouldBe true }
            this.reserved2?.let { it.value.contentEquals(that.reserved2?.value) shouldBe true }
            this.reserved3?.let { it.value.contentEquals(that.reserved3?.value) shouldBe true }
        }

        infix fun OperationalCSRInfo.shouldBeSimilarTo(that: OperationalCSRInfo) {
            this.opCSR shouldBeSimilarTo that.opCSR
            this.signature.value contentEquals that.signature.value shouldBe true
        }

        private val dummyByteArray = byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06)

        private fun nextNumber() = Random.nextInt(0, 100).toByte()
        private fun nextBytes(size: Int) = Random.nextBytes(size)

        @JvmStatic
        private fun getKeyPurposeIds() = listOf(
            BCKeyPurposeId.id_kp_serverAuth to KeyPurposeId.SERVER_AUTH,
            BCKeyPurposeId.id_kp_clientAuth to KeyPurposeId.CLIENT_AUTH,
            BCKeyPurposeId.id_kp_codeSigning to KeyPurposeId.CODE_SIGNING,
            BCKeyPurposeId.id_kp_emailProtection to KeyPurposeId.EMAIL_PROTECTION,
            BCKeyPurposeId.id_kp_timeStamping to KeyPurposeId.TIMESTAMPING,
            BCKeyPurposeId.id_kp_OCSPSigning to KeyPurposeId.OCSP_SIGNING,
        ).map { it.toArgs() }

        @JvmStatic
        private fun getTLVKeyPurposeIds() = listOf(
            1 to KeyPurposeId.SERVER_AUTH,
            2 to KeyPurposeId.CLIENT_AUTH,
            3 to KeyPurposeId.CODE_SIGNING,
            4 to KeyPurposeId.EMAIL_PROTECTION,
            5 to KeyPurposeId.TIMESTAMPING,
            6 to KeyPurposeId.OCSP_SIGNING,
        ).map { it.toArgs() }

        @JvmStatic
        private fun getASNOids() = listOf(
            "2.5.4.3" to BCStyle.CN,
            "2.5.4.4" to BCStyle.SURNAME,
            "2.5.4.5" to BCStyle.SERIALNUMBER,
            "2.5.4.6" to BCStyle.C,
            "2.5.4.7" to BCStyle.L,
            "2.5.4.8" to BCStyle.ST,
            "2.5.4.10" to BCStyle.O,
            "2.5.4.11" to BCStyle.OU,
            "2.5.4.12" to BCStyle.T,
            "2.5.4.41" to BCStyle.NAME,
            "2.5.4.42" to BCStyle.GIVENNAME,
            "2.5.4.43" to BCStyle.INITIALS,
            "2.5.4.44" to BCStyle.GENERATION,
            "2.5.4.46" to BCStyle.DN_QUALIFIER,
            "2.5.4.65" to BCStyle.PSEUDONYM,
        ).map { it.toArgs() }

        private const val DN_ATTRIBUTE_VALUE = "42"
        private val DN_ATTRIBUTE_LONG = DNAttribute.parseULong(DN_ATTRIBUTE_VALUE)

        @JvmStatic
        private fun getDNAttributeOids() = listOf(
            BCStyle.CN.id to CommonName(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.SURNAME.id to Surname(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.SERIALNUMBER.id to SerialNum(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.C.id to CountryName(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.L.id to LocalityName(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.ST.id to StateOrProvinceName(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.O.id to OrgName(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.OU.id to OrgUnitName(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.T.id to Title(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.NAME.id to Name(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.GIVENNAME.id to GivenName(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.INITIALS.id to Initials(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.GENERATION.id to GenQualifier(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.DN_QUALIFIER.id to DnQualifier(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.PSEUDONYM.id to Pseudonym(Str(DN_ATTRIBUTE_VALUE)),
            BCStyle.DC.id to DomainComponent(Str(DN_ATTRIBUTE_VALUE)),
            Asn1Oids.RDN_CHIP_NODE_ID to ChipNodeId(DN_ATTRIBUTE_LONG),
            Asn1Oids.RDN_CHIP_FIRMWARE_SIGNING_ID to ChipFirmwareSigningId(DN_ATTRIBUTE_LONG),
            Asn1Oids.RDN_CHIP_ICA_ID to ChipIcaId(DN_ATTRIBUTE_LONG),
            Asn1Oids.RDN_CHIP_ROOT_CA_ID to ChipRootCaId(DN_ATTRIBUTE_LONG),
            Asn1Oids.RDN_CHIP_FABRIC_ID to ChipFabricId(DN_ATTRIBUTE_LONG),
            Asn1Oids.RDN_CHIP_OP_CERT_AT1 to ChipOpCertAt1(DN_ATTRIBUTE_LONG),
            Asn1Oids.RDN_CHIP_OP_CERT_AT2 to ChipOpCertAt2(DN_ATTRIBUTE_LONG),
        ).map { it.toArgs() }

        @JvmStatic
        private fun getDNAttributeElements() = listOf(
            Elem(ContextTag(1u), Str(DN_ATTRIBUTE_VALUE)) to CommonName(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(2u), Str(DN_ATTRIBUTE_VALUE)) to Surname(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(3u), Str(DN_ATTRIBUTE_VALUE)) to SerialNum(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(4u), Str(DN_ATTRIBUTE_VALUE)) to CountryName(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(5u), Str(DN_ATTRIBUTE_VALUE)) to LocalityName(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(6u), Str(DN_ATTRIBUTE_VALUE)) to StateOrProvinceName(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(7u), Str(DN_ATTRIBUTE_VALUE)) to OrgName(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(8u), Str(DN_ATTRIBUTE_VALUE)) to OrgUnitName(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(9u), Str(DN_ATTRIBUTE_VALUE)) to Title(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(10u), Str(DN_ATTRIBUTE_VALUE)) to Name(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(11u), Str(DN_ATTRIBUTE_VALUE)) to GivenName(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(12u), Str(DN_ATTRIBUTE_VALUE)) to Initials(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(13u), Str(DN_ATTRIBUTE_VALUE)) to GenQualifier(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(14u), Str(DN_ATTRIBUTE_VALUE)) to DnQualifier(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(15u), Str(DN_ATTRIBUTE_VALUE)) to Pseudonym(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(16u), Str(DN_ATTRIBUTE_VALUE)) to DomainComponent(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(17u), DN_ATTRIBUTE_LONG) to ChipNodeId(DN_ATTRIBUTE_LONG),
            Elem(ContextTag(18u), DN_ATTRIBUTE_LONG) to ChipFirmwareSigningId(DN_ATTRIBUTE_LONG),
            Elem(ContextTag(19u), DN_ATTRIBUTE_LONG) to ChipIcaId(DN_ATTRIBUTE_LONG),
            Elem(ContextTag(20u), DN_ATTRIBUTE_LONG) to ChipRootCaId(DN_ATTRIBUTE_LONG),
            Elem(ContextTag(21u), DN_ATTRIBUTE_LONG) to ChipFabricId(DN_ATTRIBUTE_LONG),
            Elem(ContextTag(22u), DN_ATTRIBUTE_LONG) to ChipOpCertAt1(DN_ATTRIBUTE_LONG),
            Elem(ContextTag(23u), DN_ATTRIBUTE_LONG) to ChipOpCertAt2(DN_ATTRIBUTE_LONG),
            Elem(ContextTag(129u), Str(DN_ATTRIBUTE_VALUE)) to CommonNamePs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(130u), Str(DN_ATTRIBUTE_VALUE)) to SurnamePs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(131u), Str(DN_ATTRIBUTE_VALUE)) to SerialNumPs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(132u), Str(DN_ATTRIBUTE_VALUE)) to CountryNamePs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(133u), Str(DN_ATTRIBUTE_VALUE)) to LocalityNamePs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(134u), Str(DN_ATTRIBUTE_VALUE)) to StateOrProvincePamePs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(135u), Str(DN_ATTRIBUTE_VALUE)) to OrgNamePs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(136u), Str(DN_ATTRIBUTE_VALUE)) to OrgUnitPamePs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(137u), Str(DN_ATTRIBUTE_VALUE)) to TitlePs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(138u), Str(DN_ATTRIBUTE_VALUE)) to NamePs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(139u), Str(DN_ATTRIBUTE_VALUE)) to GivenNamePs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(140u), Str(DN_ATTRIBUTE_VALUE)) to InitialsPs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(141u), Str(DN_ATTRIBUTE_VALUE)) to GenQualifierPs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(142u), Str(DN_ATTRIBUTE_VALUE)) to DnQualifierPs(Str(DN_ATTRIBUTE_VALUE)),
            Elem(ContextTag(143u), Str(DN_ATTRIBUTE_VALUE)) to PseudonymPs(Str(DN_ATTRIBUTE_VALUE)),
        ).map { it.toArgs() }
    }
}
