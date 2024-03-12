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

import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/** @author youtube */
public class ParmGenToken implements DeepClone {

    ParmGenTokenKey ptk;
    ParmGenTokenValue ptv;
    Boolean enabled = false;

    ParmGenToken(
            AppValue.TokenTypeNames _tokentype,
            String url,
            String name,
            String value,
            Boolean _b,
            int fcnt) {
        ptk = new ParmGenTokenKey(_tokentype, name, fcnt);
        ptv = new ParmGenTokenValue(url, value, _b);
    }

    ParmGenToken(ParmGenTokenKey tkey, ParmGenTokenValue tval) {
        ptk = tkey;
        ptv = tval;
    }

    ParmGenToken(ParmGenToken tkn) {
        ptk = new ParmGenTokenKey(tkn.ptk);
        ptv = new ParmGenTokenValue(tkn.ptv);
        enabled = tkn.enabled;
    }

    public ParmGenTokenKey getTokenKey() {
        return ptk;
    }

    public ParmGenTokenValue getTokenValue() {
        return ptv;
    }

    public Boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean _enabled) {
        enabled = _enabled;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof ParmGenToken) {
            ParmGenToken tkn = (ParmGenToken) obj;
            // name is case-sensitive.
            return this.ptk.equals(tkn.ptk)
                    && this.ptv.equals(tkn.ptv)
                    && Objects.equals(this.enabled, tkn.enabled);
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {

        int hash = Objects.hash(this.enabled, this.ptk.hashCode(), this.ptv.hashCode());

        return hash;
    }

    @Override
    public ParmGenToken clone() {
        try {
            ParmGenToken nobj = (ParmGenToken) super.clone();
            // ParmGenTokenKey ptk;
            nobj.ptk = this.ptk != null ? this.ptk.clone() : null;
            // ParmGenTokenValue ptv;
            nobj.ptv = this.ptv != null ? this.ptv.clone() : null;
            // Boolean enabled = false;
            nobj.enabled = this.enabled;
            return nobj;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(ParmGenToken.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
