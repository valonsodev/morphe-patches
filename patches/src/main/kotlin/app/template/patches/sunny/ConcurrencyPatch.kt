package app.template.patches.sunny

import app.morphe.patcher.patch.intOption
import app.morphe.patcher.patch.bytecodePatch

@Suppress("unused")
val concurrencyPatch = bytecodePatch(
    name = "Increase concurrency",
    description = "Multiplies Rx and Flow flatMap concurrency by 8.",
) {
    compatibleWith(*sunnyCompatiblePackages)

    val multiplier = intOption(
        key = "multiplier",
        default = 8,
        description = "Multiplier for Rx and Flow flatMap concurrency. Must be between 1 and 127.",
        validator = { value -> value != null && value in 1..127 },
    )

    execute {
        val selectedMultiplier = multiplier.value!!

        RxFlatMapConcurrencyFingerprint.methodOrNull?.multiplyIntParameter("p2", selectedMultiplier)
        FlowFlatMapMergeConcurrencyFingerprint.methodOrNull?.multiplyIntParameter("p1", selectedMultiplier)
    }
}
