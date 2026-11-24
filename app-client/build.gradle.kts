plugins {
    id("buildsrc.convention.kotlin-jvm")
    application
}

group = "org.givashot"
version = "unspecified"

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":tls"))
}

application {
}