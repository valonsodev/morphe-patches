package dev.valonso.morphe.patches.primevideo

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.patch.resourcePatch
import app.morphe.patcher.string
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import org.w3c.dom.Element

private val NATIVE_LIBRARY_RESOURCES = mapOf(
    "armeabi-v7a" to "/native/armeabi-v7a/libpvhook.so",
    "arm64-v8a" to "/native/arm64-v8a/libpvhook.so",
)

/**
 * The containing method loads Prime Video's native Ignite libraries. Waiting
 * for the main library makes the Zig hook installation synchronous and avoids
 * a polling worker.
 */
private object IgniteNativeLibraryLoaderFingerprint : Fingerprint(
    filters = listOf(
        string("ignite-android-support"),
        string("ignite"),
    ),
)

/**
 * Internal dependency that places the native hook in the target
 * APK. It is unnamed, so Morphe exposes only [removePrimeVideoAdsPatch].
 */
private val bundlePrimeVideoNativeHookPatch = resourcePatch {
    compatibleWith(PRIME_VIDEO_COMPATIBILITY)

    execute {
        NATIVE_LIBRARY_RESOURCES.forEach { (abi, resource) ->
            val nativeLibrary = object {}.javaClass
                .getResourceAsStream(resource)
                ?.use { it.readBytes() }
                ?: error("Missing bundled native hook $resource")

            get("lib/$abi/libpvhook.so", copy = false).apply {
                parentFile.mkdirs()
                writeBytes(nativeLibrary)
            }
        }

        document("AndroidManifest.xml").use { document ->
            val application = document
                .getElementsByTagName("application")
                .item(0) as Element
            application.setAttribute("android:extractNativeLibs", "true")
        }
    }
}

@Suppress("unused")
val removePrimeVideoAdsPatch = bytecodePatch(
    name = "Remove ads",
    description = "Removes Prime Video VOD ad descriptors, pause ads, and non-linear ads.",
    default = true,
) {
    compatibleWith(PRIME_VIDEO_COMPATIBILITY)
    dependsOn(bundlePrimeVideoNativeHookPatch)

    execute {
        val libraryStringMatch =
            IgniteNativeLibraryLoaderFingerprint.instructionMatches[1]
        val libraryRegister =
            libraryStringMatch
                .getInstruction<OneRegisterInstruction>()
                .registerA

        IgniteNativeLibraryLoaderFingerprint.method.addInstructions(
            libraryStringMatch.index + 2,
            """
                const-string v$libraryRegister, "pvhook"
                invoke-static {v$libraryRegister}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
            """.trimIndent(),
        )

    }
}
