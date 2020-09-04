## AutoMacrobuilder for OWASP ZAPROXY. 

AutoMacro Builder is an extension of ZAPROXY. You can test applications that need to access pages in a specific order, such as shopping carts or registration of member information. This Extension records the http request sequence of the web application, tracks the anti-CSRF token and session cookies, and can tests it by ZAPROXY tools(ActiveScan).

![LANG](https://img.shields.io/github/languages/top/gdgd009xcd/AutoMacroBuilderForZAP)
![LICENSE](https://img.shields.io/github/license/gdgd009xcd/AutoMacroBuilderForZAP)

![screenshot](https://raw.githubusercontent.com/gdgd009xcd/RELEASES/master/IMG/ZAP/AutoMacroBuilderForZAPMain.png)
 
## Description  

Click here below:　<BR>
　　<A href="https://github.com/gdgd009xcd/AutoMacroBuilderForZAP/wiki/1.0.-OverView">English</A><BR>
　　<A href="https://github.com/gdgd009xcd/AutoMacroBuilderForZAP/wiki/2.0.%E6%A6%82%E8%A6%81%EF%BC%88%E6%97%A5%E6%9C%AC%E8%AA%9E%EF%BC%89">Japanese</A> <BR>


## <A href="https://github.com/gdgd009xcd/WEBSAMPSQLINJ">gdgd009xcd/WEBSAMPSQLINJ</A> : a member registration sample web test results.
I tested member registration my sample page which has CSRF token. below is result:  

Prerequisite: AutoMacroBuilderForZAP is installed, test sequence is set up, and member users are registered.  
Scantarget: [Modify User] 3.2.moduser.php (See <A href="https://github.com/gdgd009xcd/WEBSAMPSQLINJ#sitemap">Sitemap</A>)  

<table style="font-size: 70%;">
 <tr><th>url</th><th>parameter</th><TH>ascanrules release <BR>ver 36.0.0</TH><TH>Advanced SQLInjection Scanner <BR>Ver13 beta</TH><TH><A HREF="https://github.com/gdgd009xcd/CustomActiveScanForZAP">CustomActiveScan <BR>ver0.0.1 alpha</A></TH></tr>
 <tr><td>http://localhost:8110/moduser.php</td><td>password</td><TH>NONE</TD><TD>DETECTED<BR>(time based<BR>pg_sleep(5))</TD><TD>DETECTED(boolean based)</TD></tr>
  <tr><td>http://localhost:8110/moduser.php</td><td>age</td><TH>NONE</TD><TD>DETECTED<BR>(time based<BR>pg_sleep(5))</TD><TD>DETECTED(boolean based)</TD></tr>
 </table>



## Building

The add-ons are built with [Gradle], each add-on has its own project which is located under the `addOns` project/directory.

To build all add-ons, simply run:

    ./gradlew build

in the main directory of the project, the add-ons will be placed in the directory `build/zapAddOn/bin/` of each project.

To build an add-on individually run:

    ./gradlew :addOns:<name>:build

replacing `<name>` with the name of the add-on (e.g. `reveal`).

[Gradle]: https://gradle.org/

## I don't know Gradle...
* if you are unfamiliar with Gradle and install method, please visit <A href="https://github.com/gdgd009xcd/AutoMacroBuilderForZap/wiki/1.2.-Basic-Usage#12basic-usage">here</A>.
