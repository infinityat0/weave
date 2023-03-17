package io.yolabs.libs.weavecommon.security

import io.kotlintest.matchers.collections.shouldContainAll
import io.kotlintest.shouldBe
import io.yolabs.libs.weavecommon.FileUtils
import io.yolabs.libs.weavecommon.tlv.AnonymousTag
import io.yolabs.libs.weavecommon.tlv.Elem
import io.yolabs.libs.weavecommon.tlv.UByte
import io.yolabs.libs.weavecommon.tlv.ValueArray
import io.yolabs.libs.weavecommon.tlv.WrongValueTypeError
import io.yolabs.libs.weavecommon.toArgs
import java.security.interfaces.ECPrivateKey
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

class CertAndKeyDecoderTest {

    @ParameterizedTest(name = "Should decode {0} correctly and be similar to its TLV alternative")
    @MethodSource("getCerts")
    fun `should decode node certificate`(certName: String, tlvBytes: ByteArray) {
        val tlvCert = CertAndKey.readTLVCertFromBytes(tlvBytes)
        val x509Cert = CertAndKey.readX509CertFromFile(certName)
        val convertedTLVCert = CertAndKey.x509ToTLV(x509Cert)
        tlvCert shouldBeSimilarTo convertedTLVCert
    }

    @ParameterizedTest(name = "Should decode {0} correctly")
    @MethodSource("getOperationalCerts")
    fun `should decoded operational certificates`(certName: String, tlvBytes: ByteArray) {
        assertDoesNotThrow { CertAndKey.readTLVCertFromBytes(tlvBytes) }
    }

    @Test
    fun `should be able to read a certificate from bytes`() {
        val certBytes = FileUtils.contentsOfFile("root1.crt").toByteArray()
        assertDoesNotThrow { CertAndKey.readX509CertFromBytes(certBytes) }
    }

    @Test
    fun `should be able to encode a certificate structure into TLV`() {
        val x509Cert = CertAndKey.readX509CertFromFile("root1.crt")
        val tlvCert = CertAndKey.x509ToTLV(x509Cert)
        assertDoesNotThrow { tlvCert.encode().array() }
        // We still cannot match the fidelity of encoded byte array with the original tlv bytes.
    }

    @Test
    fun `should return a structure when certificate is converted to TLV`() {
        val x509Cert = CertAndKey.readX509CertFromFile("root1.crt")
        val tlvCert = CertAndKey.x509ToTLV(x509Cert)
        assertDoesNotThrow { tlvCert.toTLV() }
    }

    @ParameterizedTest(name = "Should decode {0} correctly into a TLV Certificate and TLV Structure")
    @MethodSource("envCerts")
    fun `should decode x509 certificate into a TLV Structure`(certName: String) {
        val x509Cert = CertAndKey.readX509CertFromFile(certName)
        assertDoesNotThrow {
            val tlvCert = CertAndKey.x509ToTLV(x509Cert)
            tlvCert.toTLV()
        }
    }

    @Test
    fun `should decode EC private key from file`() {
        val privateKey = assertDoesNotThrow {
            CertAndKey.readECPrivateKeyFromFile("intermediate_ca_key_pkcs8.pem") as ECPrivateKey
        }
        privateKey.apply {
            algorithm shouldBe "EC"
            format shouldBe "PKCS#8"
        }
    }

    @Test
    fun `dencoding certificates should render same bytes as original`() {
        val bytes = TestCerts.testCert1

        val dencoded = assertDoesNotThrow {
            val cert = CertAndKey.readTLVCertFromBytes(bytes)
            cert.encode(expectedSize = bytes.size).array()
        }

        bytes contentEquals dencoded shouldBe true
    }

    @Test
    fun `should be able to dencode a certificate chain`() {
        val certList = listOf(TestCerts.intermediate1, TestCerts.nodeCert1).map {
            CertAndKey.readTLVCertFromBytes(it)
        }
        val certChain = CertChain(certList)
        val byteArray = certChain.toTLV().encode(600).array()
        val dencoded = CertChain.fromBytes(byteArray)

        dencoded.certs.size shouldBe certChain.certs.size
        dencoded.certs.first() shouldBeSimilarTo certChain.certs.first()
        dencoded.certs.last() shouldBeSimilarTo certChain.certs.last()
    }

    @Test
    fun `should throw an error when wrong array is passed`() {
        val byteArray = Elem(tag = AnonymousTag, UByte(42u)).encode(8).array()
        val exception = assertThrows<WrongValueTypeError> { CertChain.fromBytes(byteArray) }
        with(exception) {
            expected shouldBe "ValueArray"
            found shouldBe "UByte"
        }
    }

    @Test
    fun `should throw an error when array elements are not TLV Structures`() {
        val byteArray = Elem(
            tag = AnonymousTag,
            value = ValueArray(listOf(UByte(42u)))
        ).encode(8).array()

        val exception = assertThrows<WrongValueTypeError> { CertChain.fromBytes(byteArray) }
        with(exception) {
            expected shouldBe "Structure"
            found shouldBe "UByte"
        }
    }

    @Test
    fun `cannot create a cert chain with empty certificates`() {
        assertThrows<IllegalArgumentException> { CertChain(listOf()) }
    }

    companion object {
        /**
         * Compare two certificates and see if one is similar to the other.
         * We will not be comparing signatures ATM as they are not part of the certificate.
         * (and more importantly, spec and implementation differ. So, we can't compare them)
         *
         * We can't compare extensions yet as well since we might be out of order.
         */
        private infix fun TLVCertificate.shouldBeSimilarTo(that: TLVCertificate) {
            this.serialNum.serialNum.value shouldBe that.serialNum.serialNum.value
            this.signatureAlgo.algorithm shouldBe that.signatureAlgo.algorithm
            this.publicKeyAlgo.algorithm shouldBe that.publicKeyAlgo.algorithm
            this.ellipticCurveId.curveId shouldBe that.ellipticCurveId.curveId
            this.publicKey.publicKey.value shouldBe that.publicKey.publicKey.value
            this.notBefore.time shouldBe that.notBefore.time
            this.notAfter.time shouldBe that.notAfter.time

            this.issuer.list shouldContainAll that.issuer.list
            this.subject.list shouldContainAll that.subject.list
            this.extensions.list.size shouldBe that.extensions.list.size

            // this.extensions.list.first() shouldBe that.extensions.list.first()
            // this.signature.signature.value shouldBe that.signature.signature.value
        }

        @JvmStatic
        fun getCerts() = listOf(
            "root1.crt" to TestCerts.root1,
            "root2.crt" to TestCerts.root2,
            "intermediate1.crt" to TestCerts.intermediate1,
            "intermediate2.crt" to TestCerts.intermediate2,
            "nodeCert1.crt" to TestCerts.nodeCert1,
            "nodeCert2.crt" to TestCerts.nodeCert2,
            "nodeCert3.crt" to TestCerts.nodeCert3,
            "nodeCert4.crt" to TestCerts.nodeCert4,
            "nodeCert5.crt" to TestCerts.nodeCert5,
            "nodeCert6.crt" to TestCerts.nodeCert6,
            "nodeCert7.crt" to TestCerts.nodeCert7,
            "nodeCert8.crt" to TestCerts.nodeCert8,
            "nodeCert9.crt" to TestCerts.nodeCert9,
            "nodeCert10.crt" to TestCerts.nodeCert10,
        ).map { it.toArgs() }

        @JvmStatic
        fun getOperationalCerts() = listOf(
            "operationalRootCert" to TestCerts.operationalRootCert,
            "operationalIntermediateCert" to TestCerts.operationalIntermediateCert,
            "operationalNodeCert" to TestCerts.operationalNodeCert,
        ).map { it.toArgs() }

        @JvmStatic
        fun envCerts() = listOf(
            "dev-matter-attestation-ca.pem",
            "dev-matter-operational-ca.pem",
            "int-matter-attestation-ca.pem",
            "int-matter-operational-ca.pem",
        )
    }
}
