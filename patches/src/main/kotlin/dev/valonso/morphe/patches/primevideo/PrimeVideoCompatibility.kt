package dev.valonso.morphe.patches.primevideo

import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.Compatibility

internal val PRIME_VIDEO_COMPATIBILITY = Compatibility(
    name = "Prime Video",
    packageName = "com.amazon.amazonvideo.livingroom",
    apkFileType = ApkFileType.APKM,
    appIconColor = 0x00A8E1,
)
