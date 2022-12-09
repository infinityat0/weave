package io.yolabs.libs.weavecommon.security

import io.yolabs.libs.weavecommon.FileUtils
import io.yolabs.libs.weavecommon.WeaveProfileId
import io.yolabs.libs.weavecommon.tlv.Bytes
import io.yolabs.libs.weavecommon.tlv.ContextTag
import io.yolabs.libs.weavecommon.tlv.Structure
import io.yolabs.libs.weavecommon.tlv.TLVDecoder
import io.yolabs.libs.weavecommon.tlv.TLVList
import io.yolabs.libs.weavecommon.tlv.UByte
import io.yolabs.libs.weavecommon.tlv.UInt
import io.yolabs.libs.weavecommon.tlv.Value
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.Principal
import java.security.PrivateKey
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider

@Suppress("MagicNumber", "ComplexMethod", "ThrowsCount")
object CertAndKey {

    /**
     * Spec says epoch time is Jan 1, 2020 but
     * the implementation uses epoch time of Jan 1, 2000.
     * See: CHIP_spec_0.7-core-recirc-1.pdf#page=33&zoom=100,68,932
     * Section: 7.16.2.3. Epoch Time in Microseconds
     */
    private const val JAN_FIRST_2000_SECONDS = 946684800L
    private const val JAN_FIRST_2020_SECONDS = 1577836800L
    val BC_PROVIDER = BouncyCastleProvider()
    const val EC_PRIVATE_KEY_ALGORITHM = "EC"
    const val CHIP_SIGNING_ALGORITHM = "SHA256withECDSA"

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    fun readECPrivateKeyFromFile(fileName: String): PrivateKey =
        readECPrivateKey(FileUtils.contentsOfFile(fileName))

    fun readECPrivateKey(pemString: String): PrivateKey =
        KeyFactory
            .getInstance(EC_PRIVATE_KEY_ALGORITHM, BC_PROVIDER)
            .generatePrivate(PKCS8EncodedKeySpec(getPKCS8Bytes(pemString)))

    private fun getPKCS8Bytes(pemString: String): ByteArray {
        val base64Pem = pemString
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\n", "")
            .toByteArray()
        return Base64.getDecoder().decode(base64Pem)
    }

    fun readX509CertFromBytes(byteArray: ByteArray): X509Certificate =
        CertificateFactory
            .getInstance("X509", BC_PROVIDER)
            .generateCertificate(ByteArrayInputStream(byteArray)) as X509Certificate

    fun readX509CertFromFile(fileName: String): X509Certificate {
        val certBytes = FileUtils.contentsOfFile(fileName).toByteArray()
        return readX509CertFromBytes(certBytes)
    }

    fun readTLVCertFromBytes(byteArray: ByteArray): TLVCertificate {
        val element = TLVDecoder.parseBytes(byteArray, WeaveProfileId.Security)
        val structure = element.value
        require(structure is Structure) { "expected decoded element value to be a structure: found $structure" }

        var serialNum: SerialNumber? = null
        var signatureAlgo: SignatureAlgo? = null
        var issuer: Issuer? = null
        var notBefore: NotBefore? = null
        var notAfter: NotAfter? = null
        var subject: Subject? = null
        var publicKeyAlgo: PublicKeyAlgo? = null
        var ellipticCurveId: EllipticCurveId? = null
        var publicKey: PublicKey? = null
        var extensions: Extensions? = null
        var signature: SignatureBytes? = null
        structure.elements.forEach { elem ->
            with(elem) {
                require(tag is ContextTag) { "expected ContextTag while parsing element $elem" }
                when (tag.value.toUInt()) {
                    1u  -> serialNum = SerialNumber(value as Bytes)
                    2u  -> signatureAlgo = SignatureAlgo(value as UByte)
                    3u  -> issuer = tlvParseIssuer(value)
                    4u  -> notBefore = NotBefore(value as UInt)
                    5u  -> notAfter = NotAfter(value as UInt)
                    6u  -> subject = tlvParseSubject(value)
                    7u  -> publicKeyAlgo = PublicKeyAlgo(value as UByte)
                    8u  -> ellipticCurveId = EllipticCurveId(value as UByte)
                    9u  -> publicKey = PublicKey(value as Bytes)
                    10u -> extensions = tlvParseExtensions(value)
                    11u -> signature = SignatureBytes(value as Bytes)
                    else -> error("unexpected tag: $tag")
                }
            }
        }
        return TLVCertificate(
            serialNum = serialNum ?: error("missing serial number"),
            signatureAlgo = signatureAlgo ?: error("missing signature algorithm"),
            issuer = issuer ?: error("missing issuer"),
            notBefore = notBefore ?: error("missing not before"),
            notAfter = notAfter ?: error("missing not after"),
            subject = subject ?: error("missing subject"),
            publicKeyAlgo = publicKeyAlgo ?: error("missing public key algorithm"),
            ellipticCurveId = ellipticCurveId ?: error("missing elliptic curve id"),
            publicKey = publicKey ?: error("missing public key"),
            extensions = extensions ?: error("missing extensions"),
            signature = signature ?: error("missing signature")
        )
    }

    fun x509ToTLV(cert: X509Certificate): TLVCertificate =
        with(cert) {
            val publicKeyInfo =  SubjectPublicKeyInfo.getInstance(publicKey.encoded)
            TLVCertificate(
                serialNum = SerialNumber(Bytes(serialNumber.toByteArray())),
                signatureAlgo = tlvEncodeSigAlgo(sigAlgOID),
                issuer = tlvEncodeIssuer(issuerDN),
                notBefore = NotBefore(UInt((notBefore.time / 1000 - JAN_FIRST_2000_SECONDS).toUInt())),
                notAfter = NotAfter(UInt((notAfter.time / 1000 - JAN_FIRST_2000_SECONDS).toUInt())),
                subject = tlvEncodeSubject(subjectDN),
                publicKeyAlgo = tlvEncodePublicKeyAlgo(publicKeyInfo),
                ellipticCurveId = tlvEncodeCurveId(publicKeyInfo),
                publicKey = tlvEncodePublicKey(publicKeyInfo),
                // Possibly wrong: Need to account for ordering of extensions
                extensions = tlvEncodeExtensions(cert),
                // Possibly wrong: BigInt.toByteArray may have a leading 0
                signature = SignatureBytes(Bytes(signature)),
            )
        }

    private fun tlvParseIssuer(value: Value): Issuer {
        require(value is TLVList) { "failed parsing issuer tlv node. Value type mismatch. found $value" }
        val attributes = value.elements.map { DNAttribute.fromElem(it) }
        return Issuer(attributes)
    }

    private fun tlvEncodeIssuer(issuerDN: Principal): Issuer {
        val attributes = X500Name.getInstance(issuerDN).rdNs.map { rdn ->
            // Note: rdns could be multivalued. We have to account for that
            with(rdn.first) {
                DNAttribute.fromOid(type, value.toString())
            }
        }
        return Issuer(attributes)
    }

    private fun tlvParseSubject(value: Value): Subject {
        require(value is TLVList) { "failed parsing issuer tlv node. Value type mismatch. found $value" }
        val attributes = value.elements.map { DNAttribute.fromElem(it) }
        return Subject(attributes)
    }

    private fun tlvEncodeSubject(subjectDN: Principal): Subject {
        val attributes = X500Name.getInstance(subjectDN).rdNs.map { rdn ->
            with(rdn.first) {
                DNAttribute.fromOid(type, value.toString())
            }
        }
        return Subject(attributes)
    }

    private fun tlvEncodeSigAlgo(sigAlgOID: String) =
        when (sigAlgOID) {
            X9ObjectIdentifiers.ecdsa_with_SHA256.id -> SignatureAlgo(UByte(1u))
            else -> error("Unsupported signature algorithm $sigAlgOID")
        }

    private fun tlvEncodePublicKeyAlgo(publicKeyInfo: SubjectPublicKeyInfo): PublicKeyAlgo {
        val algId = publicKeyInfo.algorithm.algorithm.id
        return when (algId) {
            Asn1Oids.EC_PUBLIC_KEY_ASN1_OID -> PublicKeyAlgo(UByte(1u))
            else -> error("Unsupported public key algorithm: $algId")
        }
    }

    private fun tlvEncodeCurveId(publicKeyInfo: SubjectPublicKeyInfo): EllipticCurveId {
        val curveId = (publicKeyInfo.algorithm.parameters as ASN1ObjectIdentifier).id
        return when (curveId) {
            Asn1Oids.EC_CURVE_ID_ASN1_OID -> EllipticCurveId(UByte(1u))
            else -> error("Unsupported public key algorithm curve-id: $curveId")
        }
    }

    private fun tlvEncodePublicKey(publicKeyInfo: SubjectPublicKeyInfo): PublicKey {
        val publicKeyData = publicKeyInfo.publicKeyData
        return PublicKey(Bytes(publicKeyData.bytes))
    }

    private fun tlvParseExtensions(element: Value): Extensions {
        require(element is TLVList) { "failed parsing extensions tlv node. Value type mismatch. found $element" }
        val extensions = element.elements.map { Extension.fromElem(it) }
        return Extensions(extensions)
    }

    private fun tlvEncodeExtensions(cert: X509Certificate): Extensions {
        val allExtensions = cert.criticalExtensionOIDs + cert.nonCriticalExtensionOIDs
        val extensionList = allExtensions.mapNotNull { extensionOid ->
            when (extensionOid) {
                Asn1Oids.BASIC_CONSTRAINTS_EXT -> {
                    val pathLength = cert.basicConstraints
                    val isCA = pathLength != -1
                    Extension.BasicConstraints(isCA, UByte(pathLength.toUByte()))
                }
                Asn1Oids.KEY_USAGE_EXT -> {
                    val keyUsages = cert.keyUsage.mapIndexed { index, item ->
                        if (item) Extension.KeyUsages.USAGE_LIST[index] else null
                    }.filterNotNull()
                    Extension.KeyUsages(keyUsages)
                }
                Asn1Oids.EXTENDED_KEY_USAGE_EXT -> {
                    val keyPurposeIds = cert.extendedKeyUsage.map {
                        Extension.KeyPurposeId.fromOid(it)
                    }
                    Extension.ExtendedKeyUsage(keyPurposeIds)
                }
                Asn1Oids.AUTHORITY_KEY_IDENTIFIER_EXT -> {
                    val extensionValue = cert.getExtensionValue(extensionOid)
                    val extSequence = JcaX509ExtensionUtils.parseExtensionValue(extensionValue)
                    val keyId = AuthorityKeyIdentifier.getInstance(extSequence).keyIdentifier
                    Extension.AuthorityKeyId(Bytes(keyId))
                }
                Asn1Oids.SUBJECT_KEY_IDENTIFIER_EXT -> {
                    val extensionValue = cert.getExtensionValue(extensionOid)
                    val extSequence = JcaX509ExtensionUtils.parseExtensionValue(extensionValue)
                    val keyId = SubjectKeyIdentifier.getInstance(extSequence).keyIdentifier
                    Extension.SubjectKeyId(Bytes(keyId))
                }
                // Everything else is a future extension. There may be many future extensions in the certificate.
                else -> Extension.FutureExtension(Bytes(cert.getExtensionValue(extensionOid)))
            }
        }
        // Not knowing any order, let's sort by their tag values
        return Extensions(extensionList.sortedBy { it.tag.value })
    }

//    Reference methods from here: Mostly unused by the library
//    fun x509EncodeDate(tlvTime: UInt): Date {
//        val msSince1970 = (tlvTime.value.toLong() + JAN_FIRST_2020_SECONDS) * 1000
//        return Date(msSince1970)
//    }
//
//    fun getX500Name(attributes: List<DNAttribute>): X500Name =
//        X500NameBuilder(BCStyle.INSTANCE).apply {
//            attributes.forEach { dnAttribute ->
//                val pair = dnAttribute.toRDNPair()
//                addRDN(pair.first, pair.second)
//            }
//        }.build()
//
//    fun tlvEncodeIssuer(cert: X509Certificate): Issuer {
//        val attributes = JcaX500NameUtil.getIssuer(cert).rdNs.map { rdn ->
//            with(rdn.first) { // rdn could be multi valued
//                DNAttribute.fromOid(type, value.toString())
//            }
//        }
//        return Issuer(attributes)
//    }
//
//    fun tlvParseSignature(value: Value): Signature {
//        require(value is Structure) { "Expected signature to be a structure. Found $value" }
//        require(value.elements.size == 2) {
//            "Expected signature to have two elements. Found ${value.elements.size}"
//        }
//        val r = value.elements[0].value as Bytes
//        val s = value.elements[1].value as Bytes
//        return Signature(r, s)
//    }
//
//    fun tlvEncodeSignature(signature: ByteArray): Signature =
//        when (val struct = ASN1StreamParser(signature).readObject().toASN1Primitive()) {
//            is DLSequence -> {
//                require(struct.size() == 2) { "Invalid signature structure: $struct" }
//                val rPrimitive = struct.getObjectAt(0).toASN1Primitive()
//                val sPrimitive = struct.getObjectAt(1).toASN1Primitive()
//
//                require(rPrimitive is ASN1Integer) { "Invalid signature structure: $struct" }
//                require(sPrimitive is ASN1Integer) { "Invalid signature structure: $struct" }
//
//                // TODO check if the array size is 32 and not more. We may have to drop the leading zero
//                Signature(
//                    r = Bytes(rPrimitive.value.toByteArray()),
//                    s = Bytes(sPrimitive.value.toByteArray())
//                )
//            }
//            else -> error("Unsupported signature type: $struct")
//        }
}
