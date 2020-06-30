AutoMacrobuilder for OWASP ZAPROXY.

AutoMacroBuilder is an extension for ZAPROXY. This Extension records the http request sequence of the web application in the macro, tracks the anti-CSRF token, and tests it by ZAPROXY tools(ActiveScan).


## Building

The add-ons are built with [Gradle], each add-on has its own project which is located under the `addOns` project/directory.

To build all add-ons, simply run:

    ./gradlew build

in the main directory of the project, the add-ons will be placed in the directory `build/zapAddOn/bin/` of each project.

To build an add-on individually run:

    ./gradlew :addOns:<name>:build

replacing `<name>` with the name of the add-on (e.g. `reveal`).

[Gradle]: https://gradle.org/
