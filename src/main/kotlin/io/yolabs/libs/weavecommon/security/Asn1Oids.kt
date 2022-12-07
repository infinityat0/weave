package io.yolabs.libs.weavecommon.security

import org.bouncycastle.asn1.ASN1ObjectIdentifier

object Asn1Oids {
    const val BASIC_CONSTRAINTS_EXT = "2.5.29.19"
    const val KEY_USAGE_EXT = "2.5.29.15"
    const val EXTENDED_KEY_USAGE_EXT = "2.5.29.37"
    const val SUBJECT_KEY_IDENTIFIER_EXT = "2.5.29.14"
    const val AUTHORITY_KEY_IDENTIFIER_EXT = "2.5.29.35"

    // These are unsupported and marked for future use
    private const val PRIVATE_KEY_USAGE_EXT = "2.5.29.16"
    private const val SUBJECT_ALTERNATIVE_NAME_EXT = "2.5.29.17"
    private const val NAME_CONSTRAINTS_EXT = "2.5.29.30"
    private const val ISSUER_ALTERNATIVE_NAME_EXT = "2.5.29.18"
    private const val POLICY_MAPPINGS_EXT = "2.5.29.33"
    private const val POLICY_CONSTRAINTS_EXT = "2.5.29.36"

    const val SHA256withECDSA_ASN1_OID = "1.2.840.10045.4.3.2"
    const val EC_PUBLIC_KEY_ASN1_OID = "1.2.840.10045.2.1"
    const val EC_CURVE_ID_ASN1_OID = "1.2.840.10045.3.1.7"

    const val RDN_CHIP_NODE_ID = "1.3.6.1.4.1.37244.1.1"
    const val RDN_CHIP_FIRMWARE_SIGNING_ID = "1.3.6.1.4.1.37244.1.2"
    const val RDN_CHIP_ICA_ID = "1.3.6.1.4.1.37244.1.3"
    const val RDN_CHIP_ROOT_CA_ID = "1.3.6.1.4.1.37244.1.4"
    const val RDN_CHIP_FABRIC_ID = "1.3.6.1.4.1.37244.1.5"
    const val RDN_CHIP_OP_CERT_AT1 = "1.3.6.1.4.1.37244.1.6"
    const val RDN_CHIP_OP_CERT_AT2 = "1.3.6.1.4.1.37244.1.7"

    fun asASNOid(oid: String): ASN1ObjectIdentifier = ASN1ObjectIdentifier(oid)
}
