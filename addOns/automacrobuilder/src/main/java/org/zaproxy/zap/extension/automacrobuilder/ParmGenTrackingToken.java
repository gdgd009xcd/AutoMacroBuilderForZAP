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
public class ParmGenTrackingToken {
    private ParmGenToken RToken; // Token value from HTTP Response
    private ParmGenRequestToken QToken; // Token value from HTTP reQuest
    private String regex = null; // option regex

    public ParmGenTrackingToken(
            ParmGenRequestToken _qtoken, ParmGenToken _rtoken, String optregex) {
        QToken = _qtoken;
        RToken = _rtoken;
        regex = optregex;
    }

    public ParmGenToken getResponseToken() {
        return RToken;
    }

    public ParmGenRequestToken getRequestToken() {
        return QToken;
    }

    public String getRegex() {
        return regex;
    }

    // HashMap
    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ParmGenTrackingToken) {
            ParmGenTrackingToken that = (ParmGenTrackingToken) obj;
            ParmGenRequestToken that_qtoken = that.getRequestToken();
            ParmGenRequestToken this_qtoken = this.getRequestToken();

            return this_qtoken.equals(that_qtoken);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {

        ParmGenRequestToken this_qtoken = this.getRequestToken();
        return this_qtoken.hashCode();
    }
}
