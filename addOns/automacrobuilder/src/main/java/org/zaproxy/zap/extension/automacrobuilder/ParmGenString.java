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

/** @author gdgd009xcd */
public class ParmGenString {
    private String value;
    int s;
    int e;
    boolean matched;

    ParmGenString(boolean _m, int _s, int _e, String _v) {
        s = _s;
        e = _e;
        value = _v;
        matched = _m;
    }

    public String getValue() {
        return value;
    }

    public int getStartPos() {
        return s;
    }

    public int getEndPos() {
        return e;
    }

    public boolean isMatched() {
        return matched;
    }
}
