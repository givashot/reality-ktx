package org.givashot.reality.config

import ch.qos.logback.classic.LoggerContext
import ch.qos.logback.classic.joran.JoranConfigurator
import ch.qos.logback.core.status.Status
import com.sksamuel.hoplite.ConfigAlias
import com.sksamuel.hoplite.ConfigLoaderBuilder
import com.sksamuel.hoplite.ExperimentalHoplite
import com.sksamuel.hoplite.addResourceSource
import org.slf4j.LoggerFactory

internal data class BaseConfig(val app: AppConfig.ApplicationConfig)

data class AppConfig(
    val app: ApplicationConfig,
    val logging: LoggingConfig,
    val server: ServerConfig,
) {
    data class ApplicationConfig(
        val profiles: ProfilesConfig,
    ) {
        data class ProfilesConfig(
            val active: String,
        )
    }
}

data class LoggingConfig(
    val config: String,
    val files: LoggingFiles? = null,
) {
    data class LoggingFiles(
        val path: String,
    )
}

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
fun loadAppConfig(): AppConfig {
    val base = ConfigLoaderBuilder.default()
        .addResourceSource("/application.yaml")
        .withExplicitSealedTypes()
        .build()
        .loadConfigOrThrow<BaseConfig>()
    return loadAppConfigForProfile(base.app.profiles.active)
}

@OptIn(ExperimentalHoplite::class)
internal fun loadAppConfigForProfile(profile: String): AppConfig {
    val profileConfig = ConfigLoaderBuilder.default()
        .addResourceSource("/application-$profile.yaml")
        .addResourceSource("/application.yaml")
        .withExplicitSealedTypes()
        .build()
        .loadConfigOrThrow<AppConfig>()
    return profileConfig.copy(app = AppConfig.ApplicationConfig(AppConfig.ApplicationConfig.ProfilesConfig(profile)))
}

fun configureLogging(config: AppConfig) {
    val location = config.logging.config
    require(location.startsWith("classpath:") && location.removePrefix("classpath:").isNotBlank()) {
        "logging.config must specify a classpath resource: $location"
    }
    val configurationResource = "/" + location.removePrefix("classpath:").removePrefix("/")
    val configurationUrl = AppConfig::class.java.getResource(configurationResource)
        ?: error("Logging configuration resource not found: $configurationResource")
    val logPath = config.logging.files?.path
    val loggerContext = LoggerFactory.getILoggerFactory() as? LoggerContext
        ?: error("Logback is required to configure application logging")
    loggerContext.reset()
    loggerContext.statusManager.clear()
    if (logPath != null) loggerContext.putProperty("LOG_PATH", logPath)
    JoranConfigurator().apply {
        context = loggerContext
    }.doConfigure(configurationUrl)
    val errors = loggerContext.statusManager.copyOfStatusList.filter { it.level == Status.ERROR }
    check(errors.isEmpty()) {
        "Failed to configure logging from $configurationResource: ${errors.joinToString { it.message }}"
    }
}
