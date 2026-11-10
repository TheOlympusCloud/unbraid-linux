import com.google.protobuf.gradle.id

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("org.jetbrains.compose")
    id("com.google.protobuf")
}

// Follows the Android release this port tracks.
val versionName = "2.8.2"
val cmp = "1.13.0-beta02"
val grpc = "1.85.1"
val grpcKotlin = "1.5.0"
val protobuf = "4.36.2"

kotlin {
    jvmToolchain(21)
    compilerOptions {
        // Runs on the distribution's Java, 17 or later (Debian 12's default is 17).
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        // As the Android build compiles the same screens: Material 3 Expressive and the desktop's back handling are still marked experimental.
        optIn.addAll("androidx.compose.ui.ExperimentalComposeUiApi", "androidx.compose.material3.ExperimentalMaterial3ExpressiveApi")
    }
}
tasks.withType<JavaCompile>().configureEach { options.release.set(17) }

// The Android build's BuildConfig, for the code that reads it.
val buildConfig by tasks.registering {
    val dir = layout.buildDirectory.dir("generated/buildconfig")
    val version = versionName
    inputs.property("version", version)
    outputs.dir(dir)
    doLast {
        dir.get().file("app/unbraid/BuildConfig.kt").asFile.apply { parentFile.mkdirs() }.writeText(
            "package app.unbraid\n\nobject BuildConfig {\n    const val DEBUG = false\n    const val VERSION_NAME = \"$version\"\n}\n",
        )
    }
}
sourceSets.main { kotlin.srcDir(buildConfig) }

dependencies {
    implementation("org.jetbrains.compose.desktop:desktop-jvm-linux-x64:$cmp")
    implementation("org.jetbrains.compose.material3:material3:$cmp")
    implementation("org.jetbrains.compose.ui:ui-backhandler:$cmp")
    implementation("org.jetbrains.androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
    implementation("org.jetbrains.androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.11.0")
    // Reads QR codes from a picture (an IVPN account ID).
    implementation("com.google.zxing:core:3.5.3")
    // Local statistics, in the same SQLite schema as on Android.
    implementation("org.xerial:sqlite-jdbc:3.54.1.0")
    // The engine's API: gRPC over its unix socket.
    implementation("io.grpc:grpc-netty-shaded:$grpc")
    implementation("io.grpc:grpc-protobuf-lite:$grpc")
    implementation("io.grpc:grpc-stub:$grpc")
    implementation("io.grpc:grpc-kotlin-stub:$grpcKotlin")
    // Lite: no descriptors, which the daemon's messages (USB "descriptor" fields) would clash with, and a smaller app.
    implementation("com.google.protobuf:protobuf-javalite:$protobuf")
    testImplementation("junit:junit:4.13.2")
    // The screens, composed headless and clicked through.
    testImplementation("org.jetbrains.compose.ui:ui-test-junit4:$cmp")
}

tasks.withType<Test>().configureEach {
    // Never the user's own folders; the runtime folder stays short, as unix socket paths must.
    val run = File(System.getProperty("java.io.tmpdir"), "unbraid-test-${System.getProperty("user.name")}")
    environment("XDG_DATA_HOME", layout.buildDirectory.dir("test-home").get().asFile.path)
    environment("XDG_RUNTIME_DIR", run.path)
    rootProject.file("engine/out/unbraid-engine").takeIf { it.exists() }?.let { environment("UNBRAID_ENGINE_BIN", it.path) }
    doFirst { run.mkdirs() }
}
tasks.test { filter { excludeTestsMatching("app.unbraid.EngineCheckTest") } }
// The real engine checks what the tests compiled (engine/build.sh first).
val engineTest by tasks.registering(Test::class) {
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    filter { includeTestsMatching("app.unbraid.EngineCheckTest") }
    mustRunAfter(tasks.test)
}

protobuf {
    protoc { artifact = "com.google.protobuf:protoc:$protobuf" }
    plugins {
        id("grpc") { artifact = "io.grpc:protoc-gen-grpc-java:$grpc" }
        id("grpckt") { artifact = "io.grpc:protoc-gen-grpc-kotlin:$grpcKotlin:jdk8@jar" }
    }
    generateProtoTasks {
        all().forEach {
            it.builtins { named("java") { option("lite") } }
            it.plugins { id("grpc") { option("lite") }; id("grpckt") { option("lite") } }
        }
    }
}

compose.desktop {
    application {
        mainClass = "app.unbraid.MainKt"
        // A VPN client idles in the background: a small heap that hands memory back.
        jvmArgs += listOf("-Xms32m", "-Xmx512m", "-XX:+UseSerialGC", "-Dfile.encoding=UTF-8")
        nativeDistributions {
            packageName = "unbraid"
            packageVersion = versionName
            modules("java.desktop", "java.logging", "java.naming", "java.sql", "jdk.unsupported", "jdk.crypto.ec", "java.management")
        }
    }
}
