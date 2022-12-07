package io.yolabs.libs.weavecommon

import io.kotlintest.shouldBe
import java.nio.ByteBuffer
import org.junit.jupiter.api.Test

class HexdumpTest {
    @Test
    fun `test hex dump of a byte buffer`() {
        val expected =
            """|Offset   | 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
               |----------------------------------------------------------
               |00000000 | 15 30 01 08 6a 6e 7c 02 27 e7 85 44 24 02 01 37
               |00000010 | 03 27 13 a2 00 00 00 0a 0a 0a 0a 18 26 04 58 b2
               |00000020 | 07 2a 26 05 24 4f a6 4f 37 06 26 11 44 44 33 33
               |00000030 | 27 15 0a 00 00 00 00 ab bf fa 18 24 07 01 24 08
               |00000040 | 01 30 09 41 04 dc 86 df 41 fd 7f 64 7b 06 f4 c1
               |00000050 | af 96 97 e8 51 85 5b 33 6a eb 04 2b 38 f0 2b ec
               |00000060 | 46 19 1a 92 7a e8 56 ec b3 1e 94 81 2e 88 f0 c3
               |00000070 | ff 25 a0 05 fd cf 65 f7 c2 45 bd 5d dc c0 a7 6d
               |00000080 | 32 ac c0 f0 e2 37 0a 35 01 28 01 18 30 04 14 ff
               |00000090 | 09 bf 22 a9 30 c3 52 ee 28 43 a6 9b e3 e1 8a 8f
               |000000a0 | 08 6e 05 30 05 14 0f 84 4c f6 84 73 3d ec 6c 8b
               |000000b0 | eb 28 95 4b be 1b 89 d3 a7 6c 24 02 01 36 03 04
               |000000c0 | 01 04 02 18 18 30 0b 40 43 7b f2 17 aa 67 77 23
               |000000d0 | 22 b8 7e cb 9e 94 34 d1 e3 0e 0d ca 26 09 7e 27
               |000000e0 | 9e ff 49 70 11 e3 81 7f fe 6b 2c 1b 7c 51 fa f4
               |000000f0 | d8 7f 2d f4 14 35 4d 4b e1 81 0f f0 58 6d 36 d6
               |00000100 | 44 63 ba 4d 1b ad 94 55 18""".trimMargin("|")
        val dumped = ByteBuffer.wrap(bytes).hexdump()
        dumped shouldBe expected
    }

    @Test
    fun `test hex string of a byte array`() {
        val array = byteArrayOf(0x15, 0x30, 0x01, 0x08, 0x6a, 0x6e, 0x7c, 0x02)
        array.hexString() shouldBe "153001086a6e7c02"
    }

    companion object {
        private val bytes = arrayOf(
            0x15, 0x30, 0x01, 0x08, 0x6a, 0x6e, 0x7c, 0x02, 0x27, 0xe7, 0x85, 0x44, 0x24, 0x02, 0x01, 0x37,
            0x03, 0x27, 0x13, 0xa2, 0x00, 0x00, 0x00, 0x0a, 0x0a, 0x0a, 0x0a, 0x18, 0x26, 0x04, 0x58, 0xb2,
            0x07, 0x2a, 0x26, 0x05, 0x24, 0x4f, 0xa6, 0x4f, 0x37, 0x06, 0x26, 0x11, 0x44, 0x44, 0x33, 0x33,
            0x27, 0x15, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xab, 0xbf, 0xfa, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08,
            0x01, 0x30, 0x09, 0x41, 0x04, 0xdc, 0x86, 0xdf, 0x41, 0xfd, 0x7f, 0x64, 0x7b, 0x06, 0xf4, 0xc1,
            0xaf, 0x96, 0x97, 0xe8, 0x51, 0x85, 0x5b, 0x33, 0x6a, 0xeb, 0x04, 0x2b, 0x38, 0xf0, 0x2b, 0xec,
            0x46, 0x19, 0x1a, 0x92, 0x7a, 0xe8, 0x56, 0xec, 0xb3, 0x1e, 0x94, 0x81, 0x2e, 0x88, 0xf0, 0xc3,
            0xff, 0x25, 0xa0, 0x05, 0xfd, 0xcf, 0x65, 0xf7, 0xc2, 0x45, 0xbd, 0x5d, 0xdc, 0xc0, 0xa7, 0x6d,
            0x32, 0xac, 0xc0, 0xf0, 0xe2, 0x37, 0x0a, 0x35, 0x01, 0x28, 0x01, 0x18, 0x30, 0x04, 0x14, 0xff,
            0x09, 0xbf, 0x22, 0xa9, 0x30, 0xc3, 0x52, 0xee, 0x28, 0x43, 0xa6, 0x9b, 0xe3, 0xe1, 0x8a, 0x8f,
            0x08, 0x6e, 0x05, 0x30, 0x05, 0x14, 0x0f, 0x84, 0x4c, 0xf6, 0x84, 0x73, 0x3d, 0xec, 0x6c, 0x8b,
            0xeb, 0x28, 0x95, 0x4b, 0xbe, 0x1b, 0x89, 0xd3, 0xa7, 0x6c, 0x24, 0x02, 0x01, 0x36, 0x03, 0x04,
            0x01, 0x04, 0x02, 0x18, 0x18, 0x30, 0x0b, 0x40, 0x43, 0x7b, 0xf2, 0x17, 0xaa, 0x67, 0x77, 0x23,
            0x22, 0xb8, 0x7e, 0xcb, 0x9e, 0x94, 0x34, 0xd1, 0xe3, 0x0e, 0x0d, 0xca, 0x26, 0x09, 0x7e, 0x27,
            0x9e, 0xff, 0x49, 0x70, 0x11, 0xe3, 0x81, 0x7f, 0xfe, 0x6b, 0x2c, 0x1b, 0x7c, 0x51, 0xfa, 0xf4,
            0xd8, 0x7f, 0x2d, 0xf4, 0x14, 0x35, 0x4d, 0x4b, 0xe1, 0x81, 0x0f, 0xf0, 0x58, 0x6d, 0x36, 0xd6,
            0x44, 0x63, 0xba, 0x4d, 0x1b, 0xad, 0x94, 0x55, 0x18
        ).map { it.toByte() }.toByteArray()
    }
}
