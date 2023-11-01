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

import java.io.*;

/** @author gdgd009xcd */
public class ParmGenWriteFile {
    PrintWriter pw;
    String fileName;
    String charSet;
    boolean append;
    boolean auto_flush;

    public ParmGenWriteFile(String _fileName)
            throws UnsupportedEncodingException, FileNotFoundException {
        fileName = _fileName; // ファイル名
        charSet = "utf-8"; // 文字コードセット
        append = false; // 追加モード
        auto_flush = true; // 自動フラッシュ
        open();
    }

    final void open() throws UnsupportedEncodingException, FileNotFoundException {

        pw =
                new PrintWriter(
                        new BufferedWriter(
                                new OutputStreamWriter(
                                        new FileOutputStream(new File(fileName), append),
                                        charSet)) // 省略するとシステム標準
                        ,
                        auto_flush);
        // ...

    }

    void truncate() {
        close();
        try {
            open();
        } catch (Exception ex) {
            EnvironmentVariables.plog.printException(ex);
        }
    }

    public void print(String rec) {
        if (pw != null) {
            pw.println(rec);
        }
    }

    public void close() {
        if (pw != null) {
            pw.close();
            pw = null;
        }
    }

    PrintWriter getPrintWriter() {
        return pw;
    }
}
