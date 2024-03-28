import org.zaproxy.gradle.addon.AddOnStatus

version = "1.1.19"
description = "AutoMacroBuilder for ZAP"

tasks.withType<JavaCompile> {
    options.getDebugOptions().setDebugLevel("source,lines,vars")
}

dependencies {
    //implementation(files("../../../CustomActiveScanLib/out/artifacts/CustomActiveScanLib_jar/CustomActiveScanLib.jar"))
    implementation("com.google.code.gson:gson:2.9.0")
    implementation("org.jsoup:jsoup:1.15.3")
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
        // println(project.projectDir)
        // targetExclude(listOf("somewhere/*.java", "**/automacrobuilder/**/generated/*.java")) 
        targetExclude(listOf("**/automacrobuilder/**/generated/*.java"))
    }
}

val jar by tasks.getting(Jar::class) {
    manifest {
        attributes["Multi-Release"] = "true"
    }
}

zapAddOn {
    addOnName.set("automacrobuilder")

    // addOnStatus.set(AddOnStatus.ALPHA|BETA|RELEASE)
    addOnStatus.set(AddOnStatus.BETA)

    zapVersion.set("2.13.0")

    manifest {
        author.set("gdgd009xcd")
        url.set("https://gdgd009xcd.github.io/AutoMacroBuilderForZAP/")
        repo.set("https://github.com/gdgd009xcd/AutoMacroBuilderForZAP")
        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}
