/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.automacrobuilder;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.zaproxy.zap.extension.automacrobuilder.mdepend.ClientDependent;

/** @author daike */
public class ParmVars {
    // constants , environment params.
    public static String projectdir;
    public static String parmfile = "";
    public static PLog plog;
    public static Encode enc;
    static String
            formdataenc; // iso8859-1 encoding is fully  mapped binaries for form-data binaries.
    // Proxy Authentication
    // Basic username:password(base64 encoded)
    // String ProxyAuth = "Basic Z2RnZDAwOXhjZDpzb3JyeSxwYXNzd29yZCBoYXMgY2hhbmdlZC4=";
    static String ProxyAuth;
    public static ParmGenSession session;
    static int displaylength = 10000; // JTextArea/JTextPaneç­swingã®è¡¨ç¤ºãã¤ãæ°
    private static boolean issaved = false;
    static String fileSep = "/"; // maybe unix filesystem.
    static String Version = ""; // loaded JSON format version
    public static final int TOSTEPANY = 2147483647; // StepTo number means any value
    static List<String> ExcludeMimeTypes = null;
    private static List<Pattern> ExcludeMimeTypesPatterns = null;
    private static org.apache.logging.log4j.Logger logger4j;
    //
    // static: Runs only once at startup
    //
    static {
        File log4jdir =
                new File(ClientDependent.LOG4JXML_DIR); // LOG4JXML_DIR: $HOME/.ZAP or .BurpSuite
        String fileName = "log4j2.xml";
        File logFile = new File(log4jdir, fileName);
        if (!logFile.exists()) {
            try {
                ParmGenUtil.copyFileToHome(
                        logFile.toPath(), "xml/" + fileName, "/burp/" + fileName);
            } catch (IOException ex) {
                System.out.println("can't copy log4j2.xml");
            }
        }

        if (logFile.exists()) {
            LoggerContext context = (LoggerContext) LogManager.getContext(false);
            context.setConfigLocation(logFile.toURI());
            System.out.println("log4j:" + logFile.getPath());
        } else {
            System.out.println("log4j file not found.:" + logFile.getPath());
        }

        logger4j = org.apache.logging.log4j.LogManager.getLogger();

        setExcludeMimeTypes(
                Arrays.asList(
                        "image/.*",
                        "application/pdf")); // default Content-Types that exclude ParseResponse
        // function

        fileSep = System.getProperty("file.separator");
        formdataenc = "ISO-8859-1";

        File desktop = new File(System.getProperty("user.home"), "Desktop");
        if (!desktop.exists()) {
            projectdir =
                    System.getenv("HOMEDRIVE")
                            + fileSep
                            + System.getenv("HOMEPATH")
                            + fileSep
                            + "\u30c7\u30b9\u30af\u30c8\u30c3\u30d7";
            desktop = new File(projectdir);
            if (!desktop.exists()) {
                projectdir =
                        System.getenv("HOMEDRIVE")
                                + fileSep
                                + System.getenv("HOMEPATH")
                                + fileSep
                                + "Desktop";
            }
        } else {
            projectdir = desktop.getAbsolutePath();
        }
        desktop = null;

        parmfile = projectdir + fileSep + "MacroBuilder.json";
        plog = new PLog(projectdir);
        enc = Encode.UTF_8; // default encoding.
        ProxyAuth = "";
        session = new ParmGenSession();
    }

    public static boolean isSaved() {
        return issaved;
    }

    public static void Saved() {
        issaved = true;
    }

    private static void setRegexPatternExcludeMimeType(List<String> excludeMimeTypes) {
        Pattern compiledregex = null;
        Matcher m = null;
        ExcludeMimeTypesPatterns = new ArrayList<>();
        int flags = 0;

        flags |= Pattern.MULTILINE;

        flags |= Pattern.CASE_INSENSITIVE;

        for (String regex : excludeMimeTypes) {
            try {
                ExcludeMimeTypesPatterns.add(ParmGenUtil.Pattern_compile(regex, flags));
            } catch (Exception e) {

            }
        }
    }

    public static void setExcludeMimeTypes(List<String> extypes) {
        if (extypes != null && extypes.size() > 0) {
            ExcludeMimeTypes = extypes;
            setRegexPatternExcludeMimeType(ExcludeMimeTypes);
        }
    }

    public static void clearExcludeMimeType() {
        ExcludeMimeTypes = new ArrayList<>();
        ExcludeMimeTypesPatterns = null;
    }

    public static void addExcludeMimeType(String exttype) {
        ExcludeMimeTypes.add(exttype);
    }

    public static boolean isMimeTypeExcluded(String MimeType) {
        for (Pattern pt : ExcludeMimeTypesPatterns) {
            Matcher m = pt.matcher(MimeType);
            if (m.find()) {
                return true;
            }
        }
        return false;
    }

    public static String getFileSep() {
        return fileSep;
    }

    public static int getDisplayLength() {
        return displaylength;
    }

    public static String getParmFile() {
        return parmfile;
    }

    public static void setParmFile(String v) {
        parmfile = v;
    }
}
