import org.zaproxy.gradle.addon.AddOnStatus

version = "1.2.0"
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
            // ${zapAddOn.addOnId.get()} is the subproject folder name "automacrobuilder" in addOns project folder.
            val resourcesPath = "org.zaproxy.zap.extension.${zapAddOn.addOnId.get()}.zap.resources."
            println("resourcesPath:" + resourcesPath)
            // helpset root src path is "src/main/javahelp". you must put helpsets under this directory.
            //
            // baseName and localToken are used for determinating javahelp helpset(.hs)  file path
            // In English (default) locale, %LC% token is convert to ""
            // ${resourcesPath}help.helpset.hs
            // In ja_JP locale, %LC% token is convert to "_ja_JP" then helpset file path is:
            // ${resourcesPath}help_ja_JP.helpset_ja_JP.hs
            // * if you use %LC% locale token, then you must provide "all" locale specific helpset files for ZAP.
            //   otherwise you may remove %LC% to support any locale helpset in English only.
            // * if you comment out this helpSet function entirely,
            //   zaproxy expects the help directory to be in the following path:
            //
            //   ${resourcesPath}/help
            //                    help_ja_JP
            //                                                    ...
            //   ${resourcesPath} == org.zaproxy.zap.extension.automacrobuilder.zap.resources.
            //                    == [this addon's Extension package name].resources.
            //   ** Extension package name is the package name of this addon's Extension class file inherit from ExtensionAdaptor
            //      e.g.  The package name of ExtensionAutoMacroBuilder class.
            //
            //
            //   ** this help directory hierarchy will be used for providing localization help by crowdin in the future.
            //
            // ----locale supported helpset configurations.---
            baseName.set("${resourcesPath}help%LC%.helpset")
            localeToken.set("%LC%")
            // ---- no locale supported(English only) configurations.---
            //baseName.set("${resourcesPath}help.helpset")
            //localeToken.set("")
        }


    }
}
