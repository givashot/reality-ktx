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
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(25)
}

tasks.test {
    useJUnitPlatform()
}