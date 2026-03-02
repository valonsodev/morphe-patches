package app.template.patches.sunny

import app.morphe.patcher.patch.bytecodePatch

@Suppress("unused")
val sunnyPatch = bytecodePatch(
    name = "Disable rate limit interceptor",
    description = "Bypasses RateLimitInterceptor by returning chain.proceed(chain.request()).",
) {
    compatibleWith(*sunnyCompatiblePackages)

    execute {
        RateLimitInterceptorFingerprint.method.replaceBody(
            """
                invoke-interface {p1}, Lokhttp3/Interceptor${'$'}Chain;->request()Lokhttp3/Request;
                move-result-object v0

                invoke-interface {p1, v0}, Lokhttp3/Interceptor${'$'}Chain;->proceed(Lokhttp3/Request;)Lokhttp3/Response;
                move-result-object v0

                return-object v0
            """,
        )
    }
}
