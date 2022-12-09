package io.yolabs.libs.weavecommon.pairing

enum class DiscoveryCapabilities(val value: Int) {
    SOFT_AP(value = 0x01),
    BLE(value = 0x02),
    IP_NETWORK(value = 0x04),
    RESERVED(value = 0)
}

enum class FlowType(val value: Int) {
    STANDARD_COMMISSIONING_FLOW(value = 0x00),
    USER_INTENT_COMMISSIONING_FLOW(value = 0x01),
    CUSTOM_COMMISSIONING_FLOW(value = 0x02),
    RESERVED(value = 0x03)
}
