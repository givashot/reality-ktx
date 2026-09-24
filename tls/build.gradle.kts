plugins {
    kotlin("jvm")
}

group = "org.givashot"
version = "unspecified"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    // Source: https://mvnrepository.com/artifact/org.bouncycastle/bctls-jdk18on
    implementation(libs.bctls)
}

kotlin {
    jvmToolchain(26)
}

tasks.test {
    useJUnitPlatform()
}