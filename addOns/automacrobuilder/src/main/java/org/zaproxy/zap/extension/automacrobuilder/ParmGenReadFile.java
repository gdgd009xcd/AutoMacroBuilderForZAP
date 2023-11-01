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

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

/** @author gdgd009xcd */
public class ParmGenReadFile {

    FileReader fr = null;
    BufferedReader br = null;

    public ParmGenReadFile(String rfile) throws FileNotFoundException {
        fr = new FileReader(rfile);
        br = new BufferedReader(fr);
    }

    public String read() {

        String rdata;
        String alldata = null;
        try {
            if (br != null) {
                if ((rdata = br.readLine()) != null) {
                    rdata = rdata.replace("\r", "");
                    rdata = rdata.replace("\n", "");
                    alldata = rdata;
                }
            }
        } catch (IOException ex) {
            EnvironmentVariables.plog.printException(ex);
        }
        return alldata;
    }

    public void close() {
        if (br != null)
            try {
                br.close();
            } catch (IOException ex) {
                EnvironmentVariables.plog.printException(ex);
            }
        if (fr != null)
            try {
                fr.close();
            } catch (IOException ex) {
                EnvironmentVariables.plog.printException(ex);
            }
    }
}
