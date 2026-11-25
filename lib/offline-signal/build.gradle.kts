import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  id("java-library")
  id("org.jetbrains.kotlin.jvm")
}

java {
  sourceCompatibility = JavaVersion.toVersion(libs.versions.javaVersion.get())
  targetCompatibility = JavaVersion.toVersion(libs.versions.javaVersion.get())
}

tasks.withType<KotlinCompile>().configureEach {
  kotlin {
    compilerOptions {
      jvmTarget = JvmTarget.fromTarget(libs.versions.kotlinJvmTarget.get())
      suppressWarnings = true
    }
  }
}

dependencies {
  api(project(":lib:offline-core"))
  api(libs.libsignal.client)

  testImplementation(testLibs.junit.junit)
}
