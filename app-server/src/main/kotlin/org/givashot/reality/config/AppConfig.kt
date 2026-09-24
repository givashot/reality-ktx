package org.givashot.reality.config

import com.sksamuel.hoplite.ConfigAlias
import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.ExperimentalHoplite
import com.sksamuel.hoplite.addResourceSource

data class AppConfig(
    val server: ServerConfig,
)

data class ServerConfig(
    val port: Int,
    val reality: RealityConfig,
)

data class RealityConfig(
    @ConfigAlias("private-key")
    val privateKey: String,
    @ConfigAlias("short-ids")
    val shortIds: List<String>,
    @ConfigAlias("acceptable-snis")
    val acceptableSnis: List<String>,
    @ConfigAlias("fallback-dest")
    val fallbackDest: FallbackDest,
    @ConfigAlias("allowed-clock-skew-seconds")
    val allowedClockSkewSeconds: Int
) {

    data class FallbackDest(
        val host: String,
        val port: Int
    )

}

@OptIn(ExperimentalHoplite::class)
fun loadAppConfig(): AppConfig = ConfigLoaderBuilder.default()
    .addResourceSource("/application.yaml") // 从 classpath 加载（注意开头的斜杠 /）
    .withExplicitSealedTypes() // 顺便修复之前 Hoplite 提示的 Deprecation 警告
    .build()
    .loadConfigOrThrow()
