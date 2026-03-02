package app.template.patches.sunny

import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.extensions.InstructionExtensions.removeInstructions
import app.morphe.patcher.util.proxy.mutableTypes.MutableMethod
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation

internal val sunnyCompatiblePackages = arrayOf(
    "eu.kanade.tachiyomi",
    "eu.kanade.tachiyomi.debug",
    "xyz.jmir.tachiyomi.mi",
    "xyz.jmir.tachiyomi.mi.debug",
    "tachiyomi.mangadex",
    "tachiyomi.mangadex.debug",
    "eu.kanade.tachiyomi.j2k",
    "eu.kanade.tachiyomi.j2k.debug",
    "eu.kanade.tachiyomi.sy",
    "eu.kanade.tachiyomi.sy.debug",
    "eu.kanade.tachiyomi.az",
    "eu.kanade.tachiyomi.az.debug",
    "app.mihon",
    "app.mihon.debug",
    "eu.kanade.tachiyomi.yokai",
    "eu.kanade.tachiyomi.yokai.debug",
    "eu.kanade.tachiyomi.nightlyYokai",
    "xyz.luft.tachiyomi.mi",
    "xyz.luft.tachiyomi.mi.debug",
    "com.dark.animetailv2",
    "com.dark.animetailv2.debug",
    "app.komikku",
    "app.komikku.beta",
    "app.tachiyomi.at",
    "app.tachiyomi.at.debug",
    "eu.kanade.tachiyomi.s97",
    "eu.kanade.tachiyomi.s97.debug",
)

internal fun MutableMethod.replaceBody(instructions: String) {
    val implementation = implementation ?: error("Target method has no implementation")
    implementation.removeInstructions(implementation.instructions.size)
    implementation.clearExceptionMetadata()
    addInstructions(0, instructions)
}

private fun MutableMethodImplementation.clearExceptionMetadata() {
    val implementationClass = MutableMethodImplementation::class.java

    @Suppress("UNCHECKED_CAST")
    val tryBlocks =
        implementationClass
            .getDeclaredField("tryBlocks")
            .apply { isAccessible = true }
            .get(this) as MutableList<Any>
    tryBlocks.clear()

    @Suppress("UNCHECKED_CAST")
    val instructionLocations =
        implementationClass
            .getDeclaredField("instructionList")
            .apply { isAccessible = true }
            .get(this) as Iterable<Any>

    instructionLocations.forEach { location ->
        @Suppress("UNCHECKED_CAST")
        val debugItems = location.javaClass.getMethod("getDebugItems").invoke(location) as MutableSet<Any>
        debugItems.clear()
    }
}

internal fun MutableMethod.multiplyIntParameter(
    parameterRegister: String,
    multiplier: Int,
) {
    addInstructions(
        0,
        "mul-int/lit8 $parameterRegister, $parameterRegister, $multiplier",
    )
}
