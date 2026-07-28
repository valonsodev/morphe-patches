package dev.valonso.morphe.patches.tachiyomi

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.string

private val COMPATIBLE_PACKAGES = arrayOf(
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

private object RateLimitInterceptorFingerprint : Fingerprint(
    filters = listOf(
        string("Canceled"),
        string("Canceled"),
    ),
)

@Suppress("DEPRECATION", "unused")
val disableRateLimitPatch = bytecodePatch(
    name = "Disable rate limit",
    description = "Allows network requests to proceed without rate limiting.",
) {
    compatibleWith(*COMPATIBLE_PACKAGES)

    execute {
        val interceptMethod = RateLimitInterceptorFingerprint.methodOrNull
            ?: error("Could not find RateLimitInterceptor.intercept")

        interceptMethod.addInstructions(
            0,
            """
                invoke-interface {p1}, Lokhttp3/Interceptor${'$'}Chain;->request()Lokhttp3/Request;
                move-result-object v0
                invoke-interface {p1, v0}, Lokhttp3/Interceptor${'$'}Chain;->proceed(Lokhttp3/Request;)Lokhttp3/Response;
                move-result-object v0
                return-object v0
            """.trimIndent(),
        )
    }
}
