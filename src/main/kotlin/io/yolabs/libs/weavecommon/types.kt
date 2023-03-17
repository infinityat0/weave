package io.yolabs.libs.weavecommon

import java.io.File

data class WeaveProfileId(val vendorId: UShort, val profileId: UShort) {
    companion object {
        val Core = WeaveProfileId(vendorId = 0u, profileId = Namespaces.CORE_NAMESPACE)
        val Security = WeaveProfileId(vendorId = 0u, profileId = Namespaces.SECURITY_NAMESPACE)
    }
}

object Namespaces {
    val CORE_NAMESPACE = 0x0000u.toUShort()
    val SECURITY_NAMESPACE = 0x0008u.toUShort()
}

object FileUtils {
    fun getPath(fileName: String): String = this.javaClass.classLoader.getResource(fileName).file

    fun contentsOfFile(fileName: String): String = File(getPath(fileName)).readText(Charsets.UTF_8)
}
