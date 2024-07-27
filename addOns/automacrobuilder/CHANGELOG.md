# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [v1.2.0] - 2024-07-27
### Added
- new feature:  Added [DecodeVectorInjector](https://github.com/gdgd009xcd/AutoMacroBuilderForZAP/wiki/1.8.-encoded-parameter-injector) which enabled to decode URLencoded/base64ed parameter value for scanning or pentesting.
### Changed
- bugfix: Fixed an issue with JTextPane-like text areas where visual components such as the CR icon were lost after editing the content.

## [v1.1.20] - 2024-04-17
### Changed
- maintenance: Removed unused classes (related to "Tamper" GUI)
- bugfix: fixed bug in embeding tracking value to path

## [v1.1.19] - 2024-03-28
### Changed
- bugfix: Changed to correctly encode and decode the HttpRequest body based on Content-Encoding.

## [v1.1.18] - 2024-03-12
### Changed
- bugfix: Changed ActiveScan behavior when scan is started again.
  the current request has modified after previous scanning, so scanning again might failed.
- maintenance: Updated copyright message

## [v1.1.17] - 2024-02-29
### Changed
- bugfix: fixed bug in strange text cursor caret movement in the StyledDocumentWithChunk which has JComponents.
- bugfix: fixed bug in dissapeared CR Jlabel component while editing in the ParmGenRegex. 
- bugfix: fixed bug in getting into infinite loop after sending request which contain no contents.
- bugfix: fixed bug in problem when it cannot be displayed as ImageIcon in the StyledDocumentWithChunk.
- maintenance: Added Deprecated Annotation for no meaning doing things in PRequest.

## [v1.1.16] - 2024-02-02
### Changed
- bugfix: fixed bug in tracking token68 in Authorization bearer header(which used in OAuth2.0)
### Added
- improve: Added feature of tracking "Rails" csrf-token in meta tag 

## [v1.1.15] - 2024-01-24
### Changed
- bugfix: fixed bug in related to misuse of displaying icons in StyledDocument 

## [v1.1.14] - 2024-01-15
### Added
- improve: Added javahelp [?] button on the right-top corner of the MacroBuilder tab
### Changed
- maintenance: Removed the "Tracking Parameter" JPanel which is used only burp from the MacroBuilder Tab. 

## [v1.1.13] - 2023-12-14
### Fixed
- bugfix: Fixed "null null null" response status-line is appeared in messageView
### Changed
- maintenance: changed version of gradle-build-action from 2 to 2.11.0

## [v1.1.12] - 2023-12-12
### Added
- improve: Automacrobuilder now tracks cookies in http resposes on "ZAP's proxy".
### Fixed
- bugfix: Fixed incorrect codes in cookie state management.

## [v1.1.11] - 2023-11-29
### Changed
- bugfix: removed no meaning condition code in CSV column parameter setting.

## [v1.1.10] - 2023-11-12
### Changed
- new feature: added feature which is related to popup menu of CustomActiveScan
- new feature: Changed  behaviour of "SendMessage" popup menu. it shows animation what is doing.
- maintenance: updated typical.gif

## [v1.1.9] - 2023-11-03
### Sorry..
- bugfix: Fixed strange behaviour in file load/save actions.
### Changed
- maintenance: Refactored strange coding in some files.
- maintenance: updated typical.gif

## [v1.1.8] - 2023-11-02
### Changed
- new feature: Changed default behaviour of "AddToMacroBuilder" button. now you can scan multi-step http sequence without pushing "Track" button.
- maintenance: Refactored some files.
- bugfix: Fixed a bug in autoMacroBuilder that caused false positives in path traversal (well known path attack) checks in other scanners.
- 
## 13 - 2023-10-29
### ver1.1.7
- bugfix: Fix bug in PopUpItemSingleSend which provides manual http send message feature in AutoMacroBuilderForZAP.
- bugfix: Remove codes that uses the StyleContext.getDefaultStyleContext() method. Using this method incorrectly can have negative effects on other GUIs.

## 12 - 2023-10-18
### ver1.1.6
- improve: added new feature to "Track" button. this enabled automatically embed tracking value into Path Parameter(URL)
- bugfix: fixed problem of custom setting which embed tracking value into Path Parameter.
- maintenance: applied ”spotlessApply" to .kts files
- new feature: added [Github pages](https://gdgd009xcd.github.io/AutoMacroBuilderForZAP)

## 11 - 2023-10-08
### ver1.1.5
- maintenance: refactored properties file to Japanese Charset name to alphanumeric name.
- improvement: messageView(Request/Response/Results message viewer) move to "information area"(which attached such as history tab) in ZAP UI
- improvement: changed log message to more readable.
- maintenance: no longer used .form file. I will directly edit java code for GUI maintenance.
- upgrade: dependent "org.zaproxy.add-on" version upgraded to 0.8.0
- upgrade: gradle version upgraded to 8.2.1
- upgrade: dependent zap version upgraded to 2.13.0
- maintenance: Due to side effects of the above upgrade, some code has been changed.

## 10 - 2022-09-15
### ver1.1.2
- maintenance: updated jsoup library to the latest version
- maintenance: deleted some unnecessary codes.

## 9 - 2022-07-30
### ver1.1.1
- improve: improve performance for "Track"(auto generating parameter tracking) button action.
- bugfix: fixed some "track" button action problems.

## 8 - 2022-06-20
### ver1.1.0
- new feature: [supported simultaneous multiple sequence scanning](https://github.com/gdgd009xcd/AutoMacroBuilderForZAP/wiki/1.7.-Simultaneous-multipre-sequence-scanning)
- improve: changed to new version JSON file format
- maintenance: updated gson library to the latest version

## 7 - 2022-03-05
### ver1.0.6
- underconstruction: new feature implement

## 6 - 2021-12-15
### ver1.0.5
- maintenance: removed the log4j2 library that this add-on contains
- maintenance: upgraded ZAP dependency version  to 2.11.0

## 5 - 2021-12-11
### ver1.0.4
- maintenance: updated log4j to the latest version

## 4 - 2021-09-22
### ver1.0.3
- maintenance: update jsoup to the latest version

## 3 - 2021-06-25
### ver1.0.0
- new feature: AutoMacroBuilder now support ZAPROXY's context and authentication scheme
- improve: setting Multi-Release: true in the MANIFEST.MF file for using java 9+

## 2 - 2020-12-22

- new feature: "subsequence scan Limit" maximum number of subsequent requests after scan/resend request currently being tested.
- bugfix: unspecified request added to Macro Request List when using AddToMacorBuilder popup menu in History Panel.

## 1 - 2020-09-10

- new feature: Conditional Parameter for detecting the completion of processing.  
  See: [1.5. Conditional Parameter(ValidCondRegex).](https://github.com/gdgd009xcd/AutoMacroBuilderForZAP/wiki/1.5.-Conditional-Parameter(ValidCondRegex))

## [v0.0.0] - 1970-0101
### Added
- xxxx...xx
### Changed
### Deprecated
### Removed
### Fixed
### Security
### Sorry..


