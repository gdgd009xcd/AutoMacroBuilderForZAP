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

import com.google.gson.JsonElement;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/** @author daike */
public class GsonIterator {
    enum ElmType {
        ARRAY,
        OBJECT,
        PRIMITIVE
    }

    String keyname; // this Array's or Ojbect's keyname
    Iterator<Map.Entry<String, JsonElement>> objit;
    Iterator<JsonElement> arrit;

    GsonIterator(String k, Set<Map.Entry<String, JsonElement>> eset) {
        keyname = k;
        objit = eset.iterator();
        arrit = null;
    }

    GsonIterator(String k, Iterator<JsonElement> it) {
        keyname = k;
        arrit = it;
        objit = null;
    }

    public ElmType getElmType() {
        return (arrit != null ? ElmType.ARRAY : ElmType.OBJECT);
    }

    public boolean hasNext() {
        return arrit != null ? (arrit.hasNext()) : (objit.hasNext());
    }

    public GsonEntry next() {
        GsonEntry jent = null;
        if (hasNext()) {
            if (arrit != null) {
                JsonElement nelm = arrit.next();
                jent = new GsonEntry(nelm);
            } else {
                Map.Entry<String, JsonElement> ment = objit.next();
                String k = ment.getKey();
                JsonElement nelm = ment.getValue();
                jent = new GsonEntry(k, nelm);
            }
        }

        return jent;
    }

    public String getKeyName() {
        return keyname;
    }
}
