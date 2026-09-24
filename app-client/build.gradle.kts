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
    implementation(libs.bctls)
    implementation(project(":tls"))
    testImplementation(kotlin("test"))
}

application {
    mainClass = "org.givashot.appclient.AppClientKt"
}