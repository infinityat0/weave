package io.yolabs.libs.weavecommon.security

import io.yolabs.libs.weavecommon.security.CertAndKey.BC_PROVIDER
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.random.Random

@Suppress("MagicNumber")
object SpakeUtils {

    const val PBKDF_KEY_LENGTH_BITS = 64

    private val base64Encoder = Base64.getEncoder()
    // Check https://www.bouncycastle.org/specifications.html for algorithm names
    private val pbkdfFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", BC_PROVIDER)

    /**
     * Generates a random set of bytes to be used as Salt.
     *
     * Salt is a random value per device of at least 16 bytes and at most 32 bytes used as the PBKDF2 salt.
     */
    fun generateSpakeSalt(): ByteArray = Random.nextBytes(Random.nextInt(16, 32))

    /**
     * Encodes a given salt/hash values into Base64.
     */
    fun base64Encode(array: ByteArray): String = base64Encoder.encodeToString(array)

    /**
     * Returns the PBKDF Hash of size 256 bits. It is generated using the algorithm `PBKDF2WithHmacSHA256`
     */
    fun getPBKDFHash(
        setupPinCode: String,
        iterationCount: Int,
        salt: ByteArray
    ): ByteArray {
        val keySpec = PBEKeySpec(setupPinCode.toCharArray(), salt, iterationCount, PBKDF_KEY_LENGTH_BITS)
        return pbkdfFactory.generateSecret(keySpec).encoded
    }
}
