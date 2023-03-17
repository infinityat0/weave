package io.yolabs.libs.weavecommon.pairing

import io.kotlintest.matchers.numerics.shouldBeGreaterThan
import io.kotlintest.matchers.numerics.shouldBeLessThanOrEqual
import io.kotlintest.matchers.string.shouldNotBeBlank
import io.kotlintest.matchers.string.shouldStartWith
import io.kotlintest.shouldBe
import io.yolabs.libs.weavecommon.verhoeff.Verhoeff
import org.junit.jupiter.api.Test

class PairingUtilsTest {

    @Test
    fun `generated passcode should work`() {
        val passcode = PairingUtils.generatePasscode()
        passcode shouldBeGreaterThan 0
        passcode shouldBeLessThanOrEqual 0x7FFFFFF
    }

    @Test
    fun `generating a discriminator should work`() {
        val discriminator = PairingUtils.generateDiscriminator().toInt()
        discriminator shouldBeGreaterThan 0
        discriminator shouldBeLessThanOrEqual 0xFFF
    }

    @Test
    fun `generating a pairing code should work`() {
        with(PairingUtils) {
            val passcode = generatePasscode()
            val discriminator = generateDiscriminator()
            val pairingCode = makePairingCode(discriminator.toInt(), passcode)
            pairingCode.shouldNotBeBlank()
            Verhoeff.validate(pairingCode) shouldBe true
        }
    }

    @Test
    fun `generating a qr code string should work`() {
        with(PairingUtils) {
            val qrCodeString = generateQRCodeString(
                version = 0,
                vendorId = 42,
                productId = 42,
                capabilities = DiscoveryCapabilities.values().toList(),
                flowType = FlowType.CUSTOM_COMMISSIONING_FLOW,
                discriminator = generateDiscriminator().toInt(),
                passcode = generatePasscode(),
            )
            qrCodeString.shouldStartWith("MT")
            qrCodeString.removePrefix("MT").shouldNotBeBlank()
        }
    }
}
