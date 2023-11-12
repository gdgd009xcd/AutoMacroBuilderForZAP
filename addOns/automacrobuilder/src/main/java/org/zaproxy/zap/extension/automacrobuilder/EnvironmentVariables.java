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

import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionAutoMacroBuilder;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** @author gdgd009xcd */
public class EnvironmentVariables {
    // constants , environment params.

    /**
     * Relative path (from add-on package) to load add-on resources.
     *
     * @see Class#getResource(String)
     */
    private static final String ZAP_RESOURCES =
            "org/zaproxy/zap/extension/automacrobuilder/zap/resources";

    private static final String ZAP_RESOURCE_ABSPATH = "/" + ZAP_RESOURCES;

    public static final String ZAP_ICONS = ZAP_RESOURCE_ABSPATH + "/icon";

    private static final String ZAP_MESSAGES = ZAP_RESOURCES + "/Messages";

    private static final ResourceBundle bundle_zap = ResourceBundle.getBundle(ZAP_MESSAGES);

    public static String projectdir;

    // current file name which actually saved parameters and requests
    private static String saveFilePathName = null;
    // file chooser approved file name
    private static String choosedFilePathName = null;
    // default file name
    private static String defaultSaveFilePath = "";
    public static PLog plog;
    static String
            formdataenc; // iso8859-1 encoding is fully  mapped binaries for form-data binaries.
    // Proxy Authentication
    // Basic username:password(base64 encoded)
    // String ProxyAuth = "Basic Z2RnZDAwOXhjZDpzb3JyeSxwYXNzd29yZCBoYXMgY2hhbmdlZC4=";
    static String ProxyAuth;
    public static ParmGenSession session;
    static int displaylength = 10000; // displayable length in JTextArea/JTextPane
    private static boolean isSaved = false;
    static String fileSep = "/"; // maybe unix filesystem.
    public static String Version = ""; // loaded JSON format version
    public static final int TOSTEPANY = 2147483647; // StepTo number means any value
    static List<String> ExcludeMimeTypes = null;
    private static List<Pattern> ExcludeMimeTypesPatterns = null;
    private static org.apache.logging.log4j.Logger LOGGER4J;

    private static ExtensionAutoMacroBuilder extensionAutoMacroBuilder;

    public static String JSONFileIANACharsetName =
            Encode.UTF_8.getIANACharsetName(); // JSON file IN/OUT encoding
    public static String DefaultCSVFileIANACharsetName =
            Encode.UTF_8.getIANACharsetName(); // "Default" CSV file IN/OUT encoding

    //
    // static: Runs only once at startup
    //
    static {
        LOGGER4J = org.apache.logging.log4j.LogManager.getLogger();

        extensionAutoMacroBuilder = null;

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

        defaultSaveFilePath = projectdir + fileSep + "MacroBuilder.json";
        plog = new PLog(projectdir);
        ProxyAuth = "";
        session = new ParmGenSession();
    }

    public static boolean isSaved() {
        return isSaved;
    }

    public static void Saved(boolean b) {
        isSaved = b;
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
                LOGGER4J.error(e.getMessage(), e);
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

    public static String getSaveFilePathName() {
        if (saveFilePathName == null || saveFilePathName.isEmpty()) {
            return defaultSaveFilePath;
        }
        return saveFilePathName;
    }



    /**
     * Returns true if the file has been saved once.
     * @return
     */
    public static boolean isFileHasBeenSavedOnce() {
        return saveFilePathName !=null && !saveFilePathName.isEmpty();
    }

    /**
     * get ZAP resource string
     *
     * @param key
     * @return
     */
    public static String getZapResourceString(String key) {
        return bundle_zap.getString(key);
    }

    /**
     * update value of savePathName with choosedFilePathName
     * @param filePath
     */
    public static void commitChoosedFile(String filePath) {
        if (EnvironmentVariables.choosedFilePathName != null
                && !EnvironmentVariables.choosedFilePathName.isEmpty()
                && EnvironmentVariables.choosedFilePathName.equals(filePath)) {
            LOGGER4J.debug("commit ChoosedFile[" + choosedFilePathName + "]->[" + saveFilePathName + "]");
            EnvironmentVariables.saveFilePathName = EnvironmentVariables.choosedFilePathName;
            EnvironmentVariables.choosedFilePathName = null;
        }
    }



    /**
     *  popup load MacroBuilderJSON file chooser
     * @param parent
     * @return  choosed file name and  stored it to choosedFilePathName<BR><BR>
     */
    public static String loadMacroBuilderJSONFileChooser(Component parent) {
        File cfile = new File(getSaveFilePathName());
        String dirname = cfile.getParent();
        ParmFileFilter pFilter = new ParmFileFilter();
        JFileChooser jfc = new JFileChooser(dirname) {

            @Override
            public void approveSelection() {
                File f = getSelectedFile();
                if (getDialogType() == OPEN_DIALOG) {
                    if (!f.exists()) {
                        String m = String.format(
                                getZapResourceString(
                                        "EnvironmentVariables.loadMacroBuilderJSONFileChooser.filenotfound.message.text"),
                                f.getName());
                        JOptionPane.showMessageDialog(
                                this,
                                m,
                                getZapResourceString("EnvironmentVariables.loadMacroBuilderJSONFileChooser.filenotfound.title.text"),
                                JOptionPane.ERROR_MESSAGE);
                        LOGGER4J.debug("loadMacroBuilderJSONFileChooser !f.exists:" +m);
                        super.cancelSelection();
                        return;
                    } else if(!getFileFilter().accept(f)) {
                        String m = String.format(getZapResourceString(
                                "EnvironmentVariables.loadMacroBuilderJSONFileChooser.noaccept.message.text"),
                                f.getName(), getFileFilter().toString());
                        JOptionPane.showMessageDialog(this, m, getZapResourceString(
                                "EnvironmentVariables.loadMacroBuilderJSONFileChooser.noaccept.title.text"),
                                JOptionPane.ERROR_MESSAGE);
                        LOGGER4J.debug("loadMacroBuilderJSONFileChooser !getFileFilter().accept(f):" +m);
                        super.cancelSelection();
                        return;
                    }
                }
                super.approveSelection();
            }
        };


        jfc.setFileFilter(pFilter);
        jfc.setAcceptAllFileFilterUsed(false);

        int fileChooserSelection = jfc.showOpenDialog(parent);// OPEN_DIALOG

        EnvironmentVariables.choosedFilePathName = null;

        switch (fileChooserSelection) {
            case JFileChooser.APPROVE_OPTION:
                //code to handle choosed file here.
                File file = jfc.getSelectedFile();
                String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");
                LOGGER4J.debug("loadMacroBuilderJSONFileChooser APPROVED[" + name +"]");
                EnvironmentVariables.choosedFilePathName = name;
                break;
            default:
                break;
        }
        return EnvironmentVariables.choosedFilePathName;
    }

    /**
     * popup save MacroBuilderJSON file chooser
     * @param parent
     * @return  choosed file name and  stored it to choosedFilePathName<BR><BR>
     */
    public static String saveMacroBuilderJSONFileChooser(Component parent) {
        File cfile = new File(getSaveFilePathName());
        String dirname = cfile.getParent();
        JFileChooser jfc = new JFileChooser(dirname){
            @Override
            public void approveSelection() {
                File f = getSelectedFile();
                if (getDialogType() == SAVE_DIALOG) {
                    if (f.exists()){
                        if(f.isFile() && getFileFilter().accept(f)) {// overwrite warning
                            String m = String.format(getZapResourceString(
                                    "EnvironmentVariables.saveMacroBuilderJSONFileChooser.confirm.message.text"),
                                    f.getName());
                            LOGGER4J.debug("[" + m + "]");
                            int rv = JOptionPane.showConfirmDialog(
                                    this, m, getZapResourceString(
                                            "EnvironmentVariables.saveMacroBuilderJSONFileChooser.confirm.title.text"),
                                    JOptionPane.YES_NO_OPTION);
                            if (rv != JOptionPane.YES_OPTION) {
                                super.cancelSelection();
                                return;
                            }
                        } else {// no json file
                            String m = String.format(getZapResourceString(
                                            "EnvironmentVariables.saveMacroBuilderJSONFileChooser.noaccept.message.text"),
                                    f.getName(), getFileFilter().toString());
                            JOptionPane.showMessageDialog(this, m, getZapResourceString(
                                            "EnvironmentVariables.saveMacroBuilderJSONFileChooser.noaccept.title.text"),
                                    JOptionPane.ERROR_MESSAGE);
                            super.cancelSelection();
                            return;
                        }
                    } else if (!getFileFilter().accept(f)) {
                        String ext = getFileFilter().toString();
                        String absPath = f.getAbsolutePath() + ext;
                        File fileWithExt = new File(absPath);
                        setSelectedFile(fileWithExt);
                        LOGGER4J.debug("saveMacroBuilderJSONFileChooser selectedfile[" + getSelectedFile().getAbsolutePath() + "]");
                    }
                }
                super.approveSelection();
            }
        };

        jfc.setSelectedFile(cfile);
        ParmFileFilter pFilter=new ParmFileFilter();
        jfc.setFileFilter(pFilter);
        jfc.setAcceptAllFileFilterUsed(false);

        EnvironmentVariables.choosedFilePathName = null;
        int fileChooserSelection = jfc.showSaveDialog(parent);
        switch(fileChooserSelection) {
            case JFileChooser.APPROVE_OPTION:
                //code to handle choosed file here.
                File file = jfc.getSelectedFile();
                String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");
                EnvironmentVariables.choosedFilePathName = name;
                LOGGER4J.debug("saveMacroBuilderJSONFileChooser APPROVED[" + name +"]");
                break;
            default:
                break;
        }

        return EnvironmentVariables.choosedFilePathName;
    }

    public static void setExtensionAutoMacroBuilder(ExtensionAutoMacroBuilder extensionAutoMacroBuilder) {
        EnvironmentVariables.extensionAutoMacroBuilder = extensionAutoMacroBuilder;
    }

    private static void callCleanUp() {
        if (EnvironmentVariables.extensionAutoMacroBuilder != null) {
            EnvironmentVariables.extensionAutoMacroBuilder.cleanUp();
        }
    }

    private static ParmGenMacroTraceProvider getParmGenMacroTraceProvider() {
        if (EnvironmentVariables.extensionAutoMacroBuilder != null) {
            return EnvironmentVariables.extensionAutoMacroBuilder.getParmGenMacroTraceProvider();
        }
        return null;
    }

    public static ParmGenMacroTrace getBaseInstanceOfParmGenMacroTrace(int tabIndex) {
        ParmGenMacroTraceProvider pmtProvider = getParmGenMacroTraceProvider();
        if (pmtProvider != null) {
            return pmtProvider.getBaseInstance(tabIndex);
        }
        return null;
    }

    public static MacroBuilderUI getMacroBuilderUI() {
        if (EnvironmentVariables.extensionAutoMacroBuilder != null) {
            MacroBuilderUI ui = EnvironmentVariables.extensionAutoMacroBuilder.getMacroBuilderUI();
            return ui;
        }
        return null;
    }
}
