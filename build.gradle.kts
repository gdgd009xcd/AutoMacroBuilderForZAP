plugins {
    id("com.diffplug.spotless") version "6.20.0"
    id("com.github.ben-manes.versions") version "0.49.0"
    // Apply the java-library plugin to add support for Java Library
    //`java-library`
}

allprojects {
    apply(plugin = "com.diffplug.spotless")
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
