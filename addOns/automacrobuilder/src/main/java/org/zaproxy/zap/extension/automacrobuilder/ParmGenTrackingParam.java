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

import java.util.logging.Level;
import java.util.logging.Logger;

/** @author gdgd009xcd */
public class ParmGenTrackingParam implements DeepClone {
    private String cachevalue = null;
    private String oldvalue = null; // previous cachevalue
    private boolean condValid =
            false; // if hasCond && !condValid then restore cachevalue from oldvalue
    private int responseStepNo = -1;

    ParmGenTrackingParam() {
        init();
    }

    private void init() {
        cachevalue = null;
        oldvalue = null;
        responseStepNo = -1;
        condValid = false;
    }

    void setValue(String _v) {
        oldvalue = cachevalue;
        cachevalue = _v;
    }

    void rollBackValue() {
        cachevalue = oldvalue;
    }

    void overWriteOldValue() {
        oldvalue = cachevalue;
    }

    void setResponseStepNo(int _r) {
        responseStepNo = _r;
    }

    public String getValue(AppValue ap) {
        return cachevalue;
    }

    public int getResponseStepNo() {
        return responseStepNo;
    }

    /**
     * set condValid variable. if hasCond && !condValid then restored cachevalue from oldvalue
     *
     * @param b
     */
    void setCondValid(boolean b) {
        condValid = b;
    }

    boolean getCondValid() {
        return condValid;
    }

    @Override
    public ParmGenTrackingParam clone() {
        try {
            ParmGenTrackingParam nobj = (ParmGenTrackingParam) super.clone();
            nobj.init();

            nobj.cachevalue = this.cachevalue;
            nobj.responseStepNo = this.responseStepNo;
            nobj.oldvalue = this.oldvalue;
            nobj.condValid = this.condValid;

            return nobj;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(ParmGenTrackingParam.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
