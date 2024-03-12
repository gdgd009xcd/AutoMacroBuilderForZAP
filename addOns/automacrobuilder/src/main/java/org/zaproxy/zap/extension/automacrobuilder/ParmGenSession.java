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

import java.util.HashMap;

/** @author gdgd009xcd */
public class ParmGenSession {
    HashMap<String, String> map;
    // names
    public static final String K_REQUESTURLREGEX = "RequestURLRegex";
    public static final String K_RESPONSEURLREGEX = "ResponseURLRegex";
    public static final String K_RESPONSEREGEX = "ResponseRegex";
    public static final String K_RESPONSEPART = "ResponsePart";
    public static final String K_RESPONSEPOSITION = "ResponsePosition";
    public static final String K_HEADERLENGTH = "headerLength";
    public static final String K_COLUMN = "column";
    public static final String K_TOKEN = "token";
    public static final String K_TOKENTYPE = "tokentype";
    public static final String K_URLENCODE = "urlencode"; // boolean "true"|"false"
    public static final String K_TAMPERATTACKFILE = "tamperattackfile"; // 診断パターンファイル
    public static final String K_TAMPERADVANCE = "tamperadvance";
    public static final String K_TAMPERPOSITION = "tamperposition";
    public static final String K_TARGETPARAM = "targetparam";
    public static final String K_PAYLOADPOSITION = "payloadposition";
    public static final String K_FROMPOS = "frompos";
    public static final String K_TOPOS = "topos";

    ParmGenSession() {
        map = new HashMap<String, String>();
    }

    public void put(String name, String val) {
        map.put(name, val);
    }

    public void put(int i, String name, String val) {
        String k = name + ":" + Integer.toString(i); // keyname:n
        map.put(k, val);
    }

    // 指定したnameのvalue値。nameが存在しない場合はnull
    public String get(String name) {
        return map.get(name);
    }

    // 指定したname:iのvalue値。name:iが存在しない場合はnull
    public String get(int i, String name) {
        String k = name + ":" + Integer.toString(i); // keyname:n
        return map.get(k);
    }

    public void clear() {
        map.clear();
    }
}
