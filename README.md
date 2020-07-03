AutoMacrobuilder for OWASP ZAPROXY.

AutoMacro Builder is an extension of ZAPROXY. This extension generates a set of web application request sequences as a macro. Macros can track CSRF tokens and cookies. It can be performed when ActiveScan is executed.

 
Click here below:　<BR>
　　<A href="https://github.com/gdgd009xcd/AutoMacroBuilderForZAP/wiki/1.0.-OverView">English</A><BR>
　　<A href="https://github.com/gdgd009xcd/AutoMacroBuilderForZAP/wiki/2.0.%E6%A6%82%E8%A6%81%EF%BC%88%E6%97%A5%E6%9C%AC%E8%AA%9E%EF%BC%89">Japanese</A> <BR>


## Building

The add-ons are built with [Gradle], each add-on has its own project which is located under the `addOns` project/directory.

To build all add-ons, simply run:

    ./gradlew build

in the main directory of the project, the add-ons will be placed in the directory `build/zapAddOn/bin/` of each project.

To build an add-on individually run:

    ./gradlew :addOns:<name>:build

replacing `<name>` with the name of the add-on (e.g. `reveal`).

[Gradle]: https://gradle.org/
