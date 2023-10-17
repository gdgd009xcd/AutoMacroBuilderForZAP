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

import java.util.Objects;

/** @author gdgd009xcd */
public class ParmGenRequestTokenKey {

    private int fcnt;
    private String name;

    public enum RequestParamType {
        Query,
        X_www_form_urlencoded,
        Json,
        Form_data,
        Header,
        Request_Line,
        Nop
    }

    public enum RequestParamSubType {
        Default,
        Cookie,
        PathParameter,
        Bearer,
    }

    private RequestParamType rptype;
    private RequestParamSubType subtype;

    ParmGenRequestTokenKey(
            RequestParamType _rptype, RequestParamSubType _subtype, String _name, int _fcnt) {
        rptype = _rptype;
        subtype = _subtype;
        name = _name;
        fcnt = _fcnt;
    }

    ParmGenRequestTokenKey(ParmGenRequestTokenKey tk) {
        rptype = tk.rptype;
        subtype = tk.subtype;
        name = tk.name;
        fcnt = tk.fcnt;
    }

    public String getName() {
        return name;
    }

    public int getFcnt() {
        return fcnt;
    }

    public RequestParamType getRequestParamType() {
        return rptype;
    }

    public RequestParamSubType getRequestParamSubType() {
        return subtype;
    }

    /**
     * parse headerName and determine Subtype.
     *
     * @param headerName
     * @return
     */
    public static RequestParamSubType parseParamSubTypeFromHeaderName(String headerName) {
        if (headerName.toUpperCase().indexOf("AUTHORIZATION") != -1) {
            return RequestParamSubType.Bearer;
        } else if (headerName.toUpperCase().indexOf("COOKIE") != -1) {
            return RequestParamSubType.Cookie;
        }
        return RequestParamSubType.Default;
    }

    // HashMap
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ParmGenRequestTokenKey) {
            ParmGenRequestTokenKey key = (ParmGenRequestTokenKey) obj;
            // name is case-sensitive.
            return this.rptype == key.rptype
                    && this.subtype == key.subtype
                    && this.name.equals(key.name)
                    && this.fcnt == key.fcnt;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        // name is case-sensitive.
        return Objects.hash(rptype, subtype, name, fcnt);
    }
}
