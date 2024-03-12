/*
 * Copyright 2024 gdgd009xcd
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
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/** @author gdgd009xcd */
//
// Logger
//

public class PLog {
    // ã­ã°ã¬ãã«
    // 	0 - INFO
    // 1 - DEBUG
    // 2 - DETAIL
    // 3 - ALL
    public static final int C_INFO = 0;
    public static final int C_DEBUG = 1;
    public static final int C_DETAIL = 2;
    public static final int C_ALL = 3;

    int LogLevel = C_INFO;
    String logname = null;
    String comments = "";
    boolean LogfileOn;
    boolean iserror = false;
    PrintWriter Stdout = null;
    PrintWriter Stderr = null;

    PLog(String projectdir) {

        logname = projectdir + EnvironmentVariables.getFileSep() + "AppScanPermGen.log";
        LogfileOn = false; // default disable file output
        File logfile = new File(logname);
        if (!logfile.exists()) {
            debuglog(1, "started: projectdir=" + projectdir);
        }
        logfile = null;
        comments = ""; // no null
        iserror = false; // ==true then error
    }

    public void SetBurpPrintStreams(PrintWriter stdout, PrintWriter stderr) {
        Stdout = stdout;
        Stderr = stderr;
    }

    private void StdoutPrintln(String v) {
        if (Stdout != null) {
            Stdout.println(v);
        }
        System.out.println(v);
    }

    private void StderrPrintln(String v) {
        if (Stderr != null) {
            Stderr.println(v);
        }
        System.err.println(v);
    }

    public String getLogname() {
        return logname;
    }

    private String getDateTimeStr() {
        Date date1 = new Date();
        SimpleDateFormat sdf1 = new SimpleDateFormat("yyyyMMdd HH:mm:ss");
        return sdf1.format(date1);
    }

    public void printLF() {
        try {
            String v = "";
            String line = "";
            boolean append = true;
            if (LogLevel >= 0) {

                line = v + "\n";
                StdoutPrintln(line);
                if (LogfileOn) {
                    FileWriter filewriter = new FileWriter(logname, append);
                    filewriter.write(v + "\r\n");
                    filewriter.close();
                }
            }
        } catch (Exception e) {
            printException(e);
        }
    }

    public void printlog(String v, boolean append) {
        try {
            v = getDateTimeStr() + " " + v;
            if (LogLevel >= 0) {

                StdoutPrintln(v);
                if (LogfileOn) {
                    FileWriter filewriter = new FileWriter(logname, append);
                    filewriter.write(v + "\r\n");
                    filewriter.close();
                }
            }
        } catch (Exception e) {
            printException(e);
        }
    }

    public void InitPrint(String v) {
        printlog(v, false);
    }

    public void AppendPrint(String v) {
        printlog(v, true);
    }

    public boolean isLogfileOn() {
        return LogfileOn;
    }

    public void LogfileOn(boolean _on) {
        LogfileOn = _on;
    }

    public void printException(Exception e) {
        StringWriter sw = null;
        PrintWriter pw = null;

        sw = new StringWriter();
        pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        String trace = sw.toString();
        printlog(e.toString(), true);
        printlog(trace, true);

        try {
            if (sw != null) {
                sw.flush();
                sw.close();
            }
            if (pw != null) {
                pw.flush();
                pw.close();
            }
        } catch (IOException ignore) {
        }
    }

    public void printError(String v) {
        if (v == null) {
            v = "";
        }
        printlog("ERROR: " + v, true);
    }

    public void debuglog(int l, String v) {
        if (l <= LogLevel) {
            printlog(v, true);
        }
    }
}
