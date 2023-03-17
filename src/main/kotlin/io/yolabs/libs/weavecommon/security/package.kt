@file:Suppress("MagicNumber")

package io.yolabs.libs.weavecommon.security

import io.yolabs.libs.weavecommon.baIgnoringSign
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.PrivateKey
import java.security.Signature
import java.security.SignatureException
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1StreamParser
import org.bouncycastle.asn1.DERSequenceGenerator
import org.bouncycastle.asn1.DLSequence

fun verifyNonce(message: ByteArray, ecSignature: ByteArray, cert: X509Certificate): Boolean = try {
    with(Signature.getInstance(CertAndKey.CHIP_SIGNING_ALGORITHM)) {
        initVerify(cert)
        update(message)
        verify(derEncode(ecSignature))
    }
} catch (ex: SignatureException) {
    throw IllegalArgumentException("Signature verification failed", ex)
}

fun signNonce(nonce: ByteArray, key: PrivateKey): ByteArray =
    Signature.getInstance(CertAndKey.CHIP_SIGNING_ALGORITHM).apply {
        initSign(key)
        update(nonce)
    }.sign()

fun getSignatureRS(derEncodedEcSignature: ByteArray): Pair<ByteArray, ByteArray> =
    when (val struct = ASN1StreamParser(derEncodedEcSignature).readObject().toASN1Primitive()) {
        is DLSequence -> {
            require(struct.size() == 2) { "Invalid signature structure: $struct" }
            val rPrimitive = struct.getObjectAt(0).toASN1Primitive()
            val sPrimitive = struct.getObjectAt(1).toASN1Primitive()

            require(rPrimitive is ASN1Integer) { "Invalid signature structure: $struct" }
            require(sPrimitive is ASN1Integer) { "Invalid signature structure: $struct" }

            rPrimitive.value.baIgnoringSign() to sPrimitive.value.baIgnoringSign()
        }
        else -> error("Unsupported signature type: $struct")
    }

fun getECSignatureOctets(derEncodedEcSignature: ByteArray): ByteArray {
    val (r, s) = getSignatureRS(derEncodedEcSignature)
    return r + s
}

fun derEncode(signature: ByteArray): ByteArray {
    val r = ByteArray(33)
    signature.copyInto(r, 1, 0, 32)
    val s = ByteArray(33)
    signature.copyInto(s, 1, 32, 64)

    val rBigInteger = BigInteger(r)
    val sBigInteger = BigInteger(s)

    val baos = ByteArrayOutputStream(100)

    DERSequenceGenerator(baos).apply {
        addObject(ASN1Integer(rBigInteger))
        addObject(ASN1Integer(sBigInteger))
        close()
    }
    baos.close()

    return baos.toByteArray()
}
