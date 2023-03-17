package io.yolabs.libs.weavecommon.pairing

import io.yolabs.libs.weavecommon.base38.Base38Utils
import io.yolabs.libs.weavecommon.base38.orderedArray
import io.yolabs.libs.weavecommon.verhoeff.Verhoeff
import kotlin.random.Random

@Suppress("MagicNumber")
object PairingUtils {

    private const val MATTER_QR_CODE_PREFIX = "MT"
    private val invalidPasscodes = setOf(
        0,
        11111111,
        22222222,
        33333333,
        44444444,
        55555555,
        66666666,
        77777777,
        88888888,
        99999999,
        12345678,
        87654321
    )

    /**
     * Generate a passcode for pairing.
     * This gets further encoded to make a pairing code that goes on the box.
     */
    fun generatePasscode(): Int {
        var value = Random.nextBits(bitCount = 27)
        while (invalidPasscodes.contains(value)) {
            value = Random.nextBits(bitCount = 27)
        }
        return value
    }

    /**
     * A 12-bit value used to discern between multiple commissionable CHIP device advertisements.
     * This gets further encoded to make pairing code.
     */
    fun generateDiscriminator(): Short = Random.nextBits(bitCount = 12).toShort()

    /**
     * A 10-digit numeric code that can be manually entered/spoken instead of
     * scanning a QR code, which contains the information needed to commission a CHIP device.
     */
    fun makePairingCode(discriminator: Int, passcode: Int): String {
        val value = listOf(
            (discriminator shr 10),
            ((discriminator and 0x300) shl 6) or (passcode and 0x3FFF),
            (passcode shr 14),
        ).map { it.toString() }.reduce { acc, s -> acc + s }
        return value + Verhoeff.generate(value)
    }

    /**
     * See:
     * https://yolabsio.atlassian.net/wiki/spaces/D/pages/1853981032/Matter+Factory+Provisioning+Package+FT
     * for a diagram on how we have to arrange qrcode bytes.
     */
    fun generateQRCodeString(
        version: Byte = 0,
        vendorId: Int,
        productId: Int,
        capabilities: List<DiscoveryCapabilities>,
        flowType: FlowType,
        discriminator: Int,
        passcode: Int,
        tlvData: ByteArray? = null
    ): String {
        // We are doing something really tricky. Since most of the components are on byte/hex boundaries,
        // For the first 8 bytes, we are shifting them and adding them in a single long.
        // Once we have the long constructed, we will shift the entire long left by 3 to accommodate version
        // and then get corresponding bytes in LITTLE_ENDIAN(This part is quite essential) order.
        val capabilitiesSum = capabilities.sumOf { it.value }.toLong()
        val first = (vendorId and 0xFFFF) +
            ((productId and 0xFFFF) shl 16) +
            ((flowType.value and 0x0003) shl 32) +
            (capabilitiesSum shl 34) +
            ((discriminator and 0x0FFF) shl 42) +
            ((passcode and 0x0007) shl 54)
        val firstSetOfBytes = ((first shl 3) + version).orderedArray()

        val second = ((passcode and 0x7FFFF80) shr 7)
        val secondSetOfBytes = byteArrayOf(
            (second and 0xFF).toByte(),
            ((second shr 8) and 0xFF).toByte(),
            ((second shr 16) and 0xFF).toByte()
        )

        val byteArray = firstSetOfBytes + secondSetOfBytes + (tlvData ?: byteArrayOf())
        val base38String = Base38Utils.toBase38(byteArray)

        return "$MATTER_QR_CODE_PREFIX:$base38String"
    }
}
