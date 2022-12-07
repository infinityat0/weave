package io.yolabs.libs.weavecommon.verhoeff

/**
 * @see <a href="http://en.wikipedia.org/wiki/Verhoeff_algorithm">More Info</a>
 * @see <a href="http://en.wikipedia.org/wiki/Dihedral_group">Dihedral Group</a>
 * @see <a href="http://mathworld.wolfram.com/DihedralGroupD5.html">Dihedral Group Order 10</a>
 */
@Suppress("MagicNumber")
object Verhoeff {

    // The multiplication table
    private val d = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
        intArrayOf(1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
        intArrayOf(2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
        intArrayOf(3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
        intArrayOf(4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
        intArrayOf(5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
        intArrayOf(6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
        intArrayOf(7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
        intArrayOf(8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
        intArrayOf(9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
    )

    // The permutation table
    private val p = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
        intArrayOf(1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
        intArrayOf(5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
        intArrayOf(8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
        intArrayOf(9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
        intArrayOf(4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
        intArrayOf(2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
        intArrayOf(7, 0, 4, 6, 9, 1, 3, 2, 5, 8)
    )

    // The inverse table
    var inv = byteArrayOf(0, 4, 3, 2, 1, 5, 6, 7, 8, 9)

    /**
     * Generates a Verhoeff digit given a number as a String
     */
    fun generate(num: String): Byte {
        val sum = toLittleEndianIntArray(num).foldIndexed(initial = 0) { index, sum, element ->
            d[sum][p[(index + 1) % 8][element]]
        }
        return inv[sum]
    }

    /*
     * Validates that an entered number is Verhoeff compliant.
     * NB: Make sure the check digit is the last one.
     */
    fun validate(num: String): Boolean {
        val check = toLittleEndianIntArray(num).foldIndexed(initial = 0) { index, sum, element ->
            d[sum][p[index % 8][element]]
        }
        return check == 0
    }

    /*
     * Returns a little endian representation of the string digits in int array
     *
     * ```
     * toLittleEndianIntArray("37801331104534073") == [3, 7, 0, 4, 3, 5, 4, 0, 1, 1, 3, 3, 1, 0, 8, 7, 3]
     * ```
     */
    private fun toLittleEndianIntArray(num: String): IntArray =
        num.reversed().map { it - '0' }.toIntArray()
}
