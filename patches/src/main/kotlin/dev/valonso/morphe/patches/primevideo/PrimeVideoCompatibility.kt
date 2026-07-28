package dev.valonso.morphe.patches.primevideo

import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.Compatibility

internal val PRIME_VIDEO_COMPATIBILITY = Compatibility(
    name = "Prime Video",
    packageName = "com.amazon.amazonvideo.livingroom",
    apkFileType = ApkFileType.APKM,
    appIconColor = 0x00A8E1,
    targets = listOf(
        AppTarget("6.24.2+v15.5.0.300-allAbis"),
        AppTarget("6.24.4+v16.0.0.103-allAbis"),
    ),
)
