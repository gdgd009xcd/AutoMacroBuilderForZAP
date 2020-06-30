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

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/** @author youtube */
@SuppressWarnings("serial")
public class ParmGenHashMap extends HashMap<ParmGenTokenKey, ParmGenTokenValue>
        implements InterfaceCollection<Map.Entry<ParmGenTokenKey, ParmGenTokenValue>>, DeepClone {

    ParmGenHashMap() {}

    public int size() {
        return super.size();
    }

    public void addToken(
            AppValue.TokenTypeNames _tokentype,
            String url,
            String name,
            String value,
            Boolean b,
            int fcnt) {
        ParmGenTokenKey tk = new ParmGenTokenKey(_tokentype, name, fcnt);
        ParmGenTokenValue tv = new ParmGenTokenValue(url, value, b);
        super.put(tk, tv);
    }

    @Override
    public Iterator<Entry<ParmGenTokenKey, ParmGenTokenValue>> iterator() {
        return entrySet().iterator();
    }

    @Override
    public ParmGenHashMap clone() {
        ParmGenHashMap nobj = (ParmGenHashMap) super.clone();
        HashMapDeepCopy.hashMapDeepElementCloneParmGenHashMap(this, nobj);
        return nobj;
    }
}
