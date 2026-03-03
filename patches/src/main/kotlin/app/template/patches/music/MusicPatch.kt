package app.template.patches.music

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.string

private val premiumFingerprint = Fingerprint(
    filters = listOf(
        string("999"),
        string("888"),
    ),
)

@Suppress("unused")
val musicPatch = bytecodePatch(
    name = "Return true early",
    description = "Forces the matched method to return true immediately.",
) {
    compatibleWith("app.symfonik.music.player")

    execute {
        println("Target method: ${premiumFingerprint.methodOrNull?.name}")
        premiumFingerprint.methodOrNull?.addInstructions(
            0,
            """
                const/4 v0, 0x1
                return v0
            """.trimIndent(),
        )
    }
}
