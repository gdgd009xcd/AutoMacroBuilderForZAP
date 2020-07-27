import org.zaproxy.gradle.addon.AddOnStatus

version = "0.9.5"
description = "AutoMacroBuilder for ZAP"

tasks.withType<JavaCompile> {
    options.getDebugOptions().setDebugLevel("source,lines,vars")
}

dependencies {
    implementation("org.apache.logging.log4j:log4j-core:2.13.2")
    implementation("com.google.code.gson:gson:2.8.6")
    implementation("org.jsoup:jsoup:1.13.1")
}

tasks {
    val sourcesJar by creating(Jar::class) {
        archiveClassifier.set("sources")
        from(sourceSets.main.get().allSource)
    }

    artifacts {
        archives(sourcesJar)
        // archives(jar)
    }
}

sourceSets {
    main {
        java {
            exclude("org/zaproxy/zap/extension/burp/**")
        }
        resources {
            exclude("burp/log4j2.xml")
        }
    }
}

spotless {
    java {
        clearSteps()
        googleJavaFormat().aosp()
        paddedCell()
        // println(project.projectDir)
        // targetExclude(listOf("somewhere/*.java", "**/automacrobuilder/**/generated/*.java")) 
        targetExclude(listOf("**/automacrobuilder/**/generated/*.java"))
    }
}

zapAddOn {
    addOnName.set("automacrobuilder")

    // addOnStatus.set(AddOnStatus.ALPHA|BETA|RELEASE)
    addOnStatus.set(AddOnStatus.ALPHA)

    zapVersion.set("2.7.0")

    manifest {
        author.set("gdgd009xcd")
    }
}
