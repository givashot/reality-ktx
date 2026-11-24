plugins {
    kotlin("jvm")
}

group = "org.givashot"
version = "unspecified"

repositories {
    mavenCentral()
}

dependencies {
    implementation(project(":tls"))
}

kotlin {
    jvmToolchain(25)
}