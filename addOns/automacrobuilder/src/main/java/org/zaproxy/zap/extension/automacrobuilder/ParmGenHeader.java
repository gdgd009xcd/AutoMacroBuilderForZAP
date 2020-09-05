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

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;
import java.util.logging.Level;
import java.util.logging.Logger;

/** @author gdgd009xcd */
public class ParmGenHeader implements DeepClone {
    private String name; // header name
    private List<ParmGenBeen> values =
            null; // multiple same header name  which has different values header list.
    // ex  Cookie: token=1234 <- been.i = 3
    //    Cookie: goo=tokyo <- been.i = 4
    private String key_uppername; // uppercase header name

    ParmGenHeader(int _i, String _n, String _v) {
        name = _n;
        key_uppername = _n;
        if (name != null) {
            key_uppername = name.toUpperCase();
        }
        values = new ArrayList<>();
        ParmGenBeen been = new ParmGenBeen();
        been.v = _v;
        been.i = _i;
        values.add(been);
    }

    private void copyFrom(ParmGenHeader sh) {
        name = sh.name;
        values = ListDeepCopy.listDeepCopy(sh.values);
        key_uppername = sh.key_uppername;
    }

    public String getName() {
        return name;
    }

    public String getKeyUpper() {
        return key_uppername;
    }

    public void addValue(int _i, String _v) {
        ParmGenBeen been = new ParmGenBeen();
        been.i = _i;
        been.v = _v;
        values.add(been);
    }

    public ListIterator<ParmGenBeen> getValuesIter() {
        return values.listIterator();
    }

    public int getValuesSize() {
        return values.size();
    }

    @Override
    public ParmGenHeader clone() {
        try {
            ParmGenHeader nobj = (ParmGenHeader) super.clone();
            nobj.copyFrom(this);
            return nobj;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(ParmGenHeader.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }
}
