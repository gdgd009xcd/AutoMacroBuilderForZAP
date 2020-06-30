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
import java.util.logging.Level;
import java.util.logging.Logger;

/** @author daike */
public class ParmGenTokenKey implements DeepClone {
    private AppValue.TokenTypeNames tokentype;
    private int fcnt;
    private String name;

    public ParmGenTokenKey(AppValue.TokenTypeNames _tokentype, String _name, int _fcnt) {
        tokentype = _tokentype;
        name = _name;
        fcnt = _fcnt;
    }

    ParmGenTokenKey(ParmGenTokenKey tk) {
        setup(tk);
    }

    private void setup(ParmGenTokenKey tk) {
        tokentype = tk.tokentype;
        name = tk.name;
        fcnt = tk.fcnt;
    }

    public String getName() {
        return name;
    }

    public AppValue.TokenTypeNames GetTokenType() {
        return tokentype;
    }

    public int getFcnt() {
        return fcnt;
    }

    public void setTokenType(AppValue.TokenTypeNames _tktype) {
        tokentype = _tktype;
    }

    // HashMap
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ParmGenTokenKey) {
            ParmGenTokenKey key = (ParmGenTokenKey) obj;
            // name is case-sensitive.
            return this.tokentype == key.tokentype
                    && this.name.equals(key.name)
                    && this.fcnt == key.fcnt;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        // name is case-sensitive.
        return Objects.hash(tokentype, name, fcnt);
    }

    @Override
    public ParmGenTokenKey clone() {
        try {
            ParmGenTokenKey nobj = (ParmGenTokenKey) super.clone();
            nobj.setup(this);
            return nobj;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(ParmGenTokenKey.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
