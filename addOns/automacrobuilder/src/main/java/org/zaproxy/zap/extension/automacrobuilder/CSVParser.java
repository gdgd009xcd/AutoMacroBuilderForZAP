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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** @author daike */
public class CSVParser {
    static Pattern pattern =
            ParmGenUtil.Pattern_compile("(\"[^\"]*(?:\"\"[^\"]*)*\"|[^,\"]*)[ \t]*?,");
    static Matcher matcher = null;
    static String term =
            "A-----fd43214234897234----------~Terminator_---------89432091842390fdsaf---Z";

    static void Parse(String rdata) {
        rdata = rdata.replaceAll("(?:\\x0D\\x0A|[\\x0D\\x0A])?$", ",") + term;
        matcher = pattern.matcher(rdata);
    }

    static boolean getField(CSVFields csvf) {
        if (matcher.find()) {
            csvf.field = matcher.group(1);
            csvf.field = csvf.field.trim();
            csvf.field = csvf.field.replaceAll("^\"(.*)\"$", "$1");
            csvf.field = csvf.field.replaceAll("\"\"", "\"");
            if (csvf.field.equals(term)) {
                return false;
            }
            return true;
        }

        return false;
    }

    static class CSVFields {
        public String field;
    }
}
