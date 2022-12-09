package io.yolabs.libs.weavecommon.security

import io.kotlintest.matchers.shouldBeInRange
import io.kotlintest.matchers.string.shouldNotBeEmpty
import io.kotlintest.shouldBe
import io.yolabs.libs.weavecommon.pairing.PairingUtils
import org.junit.jupiter.api.Test

class SpakeUtilsTest {

    @Test
    fun `should generate spake salt correctly`() {
        with(SpakeUtils) {
            val salt = generateSpakeSalt()
            salt.size shouldBeInRange 16..32

            base64Encode(salt).shouldNotBeEmpty()
        }
    }

    @Test
    fun `should generate a PBKDF hash for a given key length`() {
        with(SpakeUtils) {
            val passcode = PairingUtils.generatePasscode()
            val salt = generateSpakeSalt()
            val hash = getPBKDFHash(passcode.toString(), iterationCount = 1000, salt)
            hash.size shouldBe PBKDF_KEY_LENGTH_BITS / 8

            val encodedHash = base64Encode(hash)
            encodedHash.shouldNotBeEmpty()
        }
    }
}
