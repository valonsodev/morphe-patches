package app.template.patches.sunny

import app.morphe.patcher.Fingerprint

object RateLimitInterceptorFingerprint : Fingerprint(
    returnType = "Lokhttp3/Response;",
    parameters = listOf("Lokhttp3/Interceptor\$Chain;"),
    custom = { method, classDef ->
        classDef.type == "Leu/kanade/tachiyomi/network/interceptor/RateLimitInterceptor;" &&
            method.name == "intercept"
    },
)

object RxFlatMapConcurrencyFingerprint : Fingerprint(
    returnType = "Lrx/Observable;",
    parameters = listOf("Lrx/functions/Func1;", "I"),
    custom = { method, classDef ->
        classDef.type == "Lrx/Observable;" &&
            method.name == "flatMap"
    },
)

object FlowFlatMapMergeConcurrencyFingerprint : Fingerprint(
    returnType = "Lkotlinx/coroutines/flow/Flow;",
    parameters = listOf("Lkotlinx/coroutines/flow/Flow;", "I", "Lkotlin/jvm/functions/Function2;"),
    custom = { method, classDef ->
        classDef.type == "Lkotlinx/coroutines/flow/FlowKt;" &&
            method.name == "flatMapMerge"
    },
)
