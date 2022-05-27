package io.yolabs.libs.weavecommon

data class WeaveProfileId(val vendorId: UShort, val profileId: UShort) {
    companion object {
        val Core = WeaveProfileId(vendorId = 0u, profileId = Namespaces.CORE_NAMESPACE)
        val Security = WeaveProfileId(vendorId = 0u, profileId = Namespaces.SECURITY_NAMESPACE)
    }
}
