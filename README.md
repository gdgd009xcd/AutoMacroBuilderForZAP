## AutoMacrobuilder for OWASP ZAPROXY. 

AutoMacro Builder is an extension of ZAPROXY. You can test applications that need to access pages in a specific order, such as shopping carts or registration of member information. This Extension records the http request sequence of the web application, tracks the anti-CSRF token and session cookies, and can tests it by ZAPROXY tools(ActiveScan).

![LANG](https://img.shields.io/github/languages/top/gdgd009xcd/AutoMacroBuilderForZAP)
![LICENSE](https://img.shields.io/github/license/gdgd009xcd/AutoMacroBuilderForZAP)

![screenshot](https://raw.githubusercontent.com/gdgd009xcd/RELEASES/master/IMG/ZAP/AutoMacroBuilderForZAPMain.png)
 
## how to use   

Click here below:　<BR>
　　<A href="https://github.com/gdgd009xcd/AutoMacroBuilderForZAP/wiki/1.0.-OverView">English manuals</A><BR>
　　<A href="https://github.com/gdgd009xcd/AutoMacroBuilderForZAP/wiki/2.0.%E6%A6%82%E8%A6%81%EF%BC%88%E6%97%A5%E6%9C%AC%E8%AA%9E%EF%BC%89">Japanese manuals</A> <BR>


##  a member registration sample web test results.
I tested member registration my sample page which has CSRF token. below is result:  

Test Environment: <A href="https://github.com/gdgd009xcd/WEBSAMPSQLINJ">WEBSAMPSQLINJ</A> Docker image(docker-compose)  
Scantarget: [Modify User] 3.2.moduser.php (See <A href="https://github.com/gdgd009xcd/WEBSAMPSQLINJ#sitemap">Sitemap</A>)  
ZAPROXY Version: 2.10.0-SNAPSHOT  
Addon: AutoMacroBuilderForZAP ver0.9.6, ActiveScan rule addons(See below).  
ZAPROXY Mode: Standard mode  

<table style="font-size: 70%;">
 <tr><th>url</th><th>parameter</th><TH>ascanrules release <BR>ver 36.0.0</TH><TH>Advanced SQLInjection Scanner <BR>Ver13 beta</TH><TH><A HREF="https://github.com/gdgd009xcd/CustomActiveScanForZAP">CustomActiveScan <BR>ver0.0.1 alpha</A></TH></tr>
 <tr><td>http://localhost:8110/moduser.php</td><td>password</td><TH>NONE</TD><TD>DETECTED<BR>(time based<BR>pg_sleep(5))</TD><TD>DETECTED(boolean based)</TD></tr>
  <tr><td>http://localhost:8110/moduser.php</td><td>age</td><TH>NONE</TD><TD>DETECTED<BR>(time based<BR>pg_sleep(5))</TD><TD>DETECTED(boolean based)</TD></tr>
 </table>



## Download & Building

The add-on is built with [Gradle]: https://gradle.org/  

To download & build this addon, simply run:  

$ git clone https://github.com/gdgd009xcd/AutoMacroBuilderForZAP.git  
$ cd AutoMacroBuilderForZAP/  
$ ./gradlew build  

The add-on will be placed in the directory `AutoMacroBuilderForZAP/addOns/automacrobuilder/build/zapAddOn/bin`

$ cd addOns/automacrobuilder/build/zapAddOn/bin  
$ ls  
automacrobuilder-alpha-0.9.7.zap  
$   

* Gradle builds may fail due to network connection timeouts for downloading dependencies. If you have such problems, please retry the gradlew command each time. or you can download addon file from [release page](https://github.com/gdgd009xcd/AutoMacroBuilderForZAP/releases)
## FAQ
FAQ is [here](https://github.com/gdgd009xcd/AutoMacroBuilderForZAP/wiki/9.1.-FAQ)

