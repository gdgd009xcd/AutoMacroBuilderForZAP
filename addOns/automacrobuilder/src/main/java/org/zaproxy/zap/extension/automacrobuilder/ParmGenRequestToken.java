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

/** @author daike */
public class ParmGenRequestToken {

    private ParmGenRequestTokenKey key = null;
    private String value = null;

    ParmGenRequestToken(
            ParmGenRequestTokenKey.RequestParamType _rptype,
            ParmGenRequestTokenKey.RequestParamSubType _subtype,
            String _name,
            String _value,
            int _fcnt) {
        key = new ParmGenRequestTokenKey(_rptype, _subtype, _name, _fcnt);
        value = _value;
    }

    public ParmGenRequestToken(ParmGenToken tkn) {
        if (tkn != null) { //  Is tkn convertable?
            switch (tkn.getTokenKey().GetTokenType()) {
                case JSON:
                    key =
                            new ParmGenRequestTokenKey(
                                    ParmGenRequestTokenKey.RequestParamType.Json,
                                    ParmGenRequestTokenKey.RequestParamSubType.Default,
                                    tkn.getTokenKey().getName(),
                                    tkn.getTokenKey().getFcnt());
                    value = tkn.getTokenValue().getValue();
                    break;
                default:
                    tkn = null;
                    break;
            }
        }

        if (tkn == null) { // We cannot convert tkn's key to ParmGenRequestTokenKey.
            key =
                    new ParmGenRequestTokenKey(
                            ParmGenRequestTokenKey.RequestParamType.Nop,
                            ParmGenRequestTokenKey.RequestParamSubType.Default,
                            "",
                            0);
            value = "";
        }
    }

    public String getValue() {
        return value;
    }

    public ParmGenRequestTokenKey getKey() {
        return key;
    }
    // HashMap
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ParmGenRequestToken) {
            ParmGenRequestToken that = (ParmGenRequestToken) obj;
            ParmGenRequestTokenKey that_key = that.getKey();
            ParmGenRequestTokenKey this_key = this.getKey();

            return this_key.equals(that_key);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {

        ParmGenRequestTokenKey this_key = this.getKey();
        return this_key.hashCode();
    }
}
