plugins {
    id("com.diffplug.gradle.spotless") version "3.27.2"
    id("com.github.ben-manes.versions") version "0.27.0"
}

allprojects {
    apply(plugin = "com.diffplug.gradle.spotless")
    apply(plugin = "com.github.ben-manes.versions")

    repositories {
        mavenCentral()
    }

    spotless {
        kotlinGradle {
            ktlint()
        }

        project.plugins.withType(JavaPlugin::class) {
            java {
                licenseHeaderFile("$rootDir/gradle/spotless/license.java")
                googleJavaFormat().aosp()
            }
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "utf-8"
        options.compilerArgs = listOf("-Xlint:all", "-Xlint:-path", "-Xlint:-options", "-Werror")
    }
}
