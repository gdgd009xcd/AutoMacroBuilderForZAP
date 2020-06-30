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

import java.util.logging.Level;
import java.util.logging.Logger;

/** @author daike */
public class ParmGenTrackingParam implements DeepClone {
    private String cachevalue = null;
    private int responseStepNo = -1;

    ParmGenTrackingParam() {
        init();
    }

    public void init() {
        cachevalue = null;
        responseStepNo = -1;
    }

    void setValue(String _v) {
        cachevalue = _v;
    }

    void setResponseStepNo(int _r) {
        responseStepNo = _r;
    }

    public String getValue() {
        return cachevalue;
    }

    public int getResponseStepNo() {
        return responseStepNo;
    }

    @Override
    public ParmGenTrackingParam clone() {
        try {
            ParmGenTrackingParam nobj = (ParmGenTrackingParam) super.clone();
            nobj.init();

            nobj.cachevalue = this.cachevalue;
            nobj.responseStepNo = this.responseStepNo;

            return nobj;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(ParmGenTrackingParam.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
