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

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ParmGenGSONDecoder implements GsonParserListener, DeepClone {

    private static org.apache.logging.log4j.Logger logger4j =
            org.apache.logging.log4j.LogManager.getLogger();
    Gson gson = null;
    JsonElement element = null;
    String jsondata = null;

    List<ParmGenToken> tknlist = null;
    HashMap<String, Integer> samenamehash = null;
    HashMap<ParmGenTokenKey, ParmGenTokenValue> map = null;

    public ParmGenGSONDecoder(String jsondata) {
        init(jsondata);
    }

    private void init(String jsondata) {
        this.jsondata = jsondata;
        gson = new Gson();
        parse(jsondata);
    }

    private void parse(String jsondata) {
        try {
            element = com.google.gson.JsonParser.parseString(jsondata);
            // parser = Json.createParser(new StringReader(jsondata));
        } catch (Exception e) {
            element = null;
            // parser = null;
        }
    }

    public String decodeStringValue(String jval) {
        String str = gson.fromJson("\"" + jval + "\"", String.class);
        return str;
    }

    /**
     * 20200315 deleted. reason: javax.json base code must be deleted for apache license public
     * ArrayList<ParmGenToken> parseJSON2Token() { // testing code.. gsonParsedJSON2Token();
     * ArrayList<ParmGenToken> gtknlist = tknlist; // testing code
     *
     * <p>tknlist = new ArrayList<ParmGenToken>(); map = new HashMap<ParmGenTokenKey,
     * ParmGenTokenValue>(); String URL = ""; if (parser != null) { String keyname = ""; String
     * value = ""; int fcnt = 0; ParmGenToken tkn = null; samenamehash = new HashMap<String,
     * Integer>(); while (parser.hasNext()) { try { JsonParser.Event event = parser.next(); switch
     * (event) { case START_ARRAY:
     *
     * <p>//ParmVars.plog.debuglog(0, "START_ARRAY NAME:" +keyname + " level:" + arraylevel); break;
     * case END_ARRAY:
     *
     * <p>//ParmVars.plog.debuglog(0, "END_ARRAY NAME:" +ep + " level:" + arraylevel); break; case
     * KEY_NAME: keyname = parser.getString(); break; case START_OBJECT: case END_OBJECT: break;
     * case VALUE_TRUE: case VALUE_FALSE: break; case VALUE_STRING: case VALUE_NUMBER: value =
     * parser.getString(); fcnt = 0; if (samenamehash.containsKey(keyname)) { fcnt =
     * samenamehash.get(keyname) + 1; } samenamehash.put(keyname, fcnt); tkn = new
     * ParmGenToken(AppValue.TokenTypeNames.JSON, URL, keyname, value, false, fcnt);
     * tknlist.add(tkn); map.put(tkn.getTokenKey(), tkn.getTokenValue()); break; case VALUE_NULL:
     * value = null; break; } } catch (Exception e) { parser = null; tknlist.clear(); break; } } }
     * // testing code. for(ParmGenToken tkn: tknlist){ if(gtknlist.indexOf(tkn)==-1){
     * logger.error("gknlist has no token[" + tkn.getTokenKey().getName() + "="
     * +tkn.getTokenValue().getValue()+ "]"); break; }else { logger.debug("gknlist has SAME token["
     * + tkn.getTokenKey().getName() + "=" +tkn.getTokenValue().getValue()+ "]"); } } // testing
     * code.
     *
     * <p>return tknlist;
     *
     * <p>}
     */
    public List<ParmGenToken> parseJSON2Token() {
        tknlist = new ArrayList<ParmGenToken>();
        map = new HashMap<ParmGenTokenKey, ParmGenTokenValue>();
        String URL = "";
        if (element != null) {
            String keyname = "";
            String value = "";
            int fcnt = 0;
            ParmGenToken tkn = null;
            samenamehash = new HashMap<String, Integer>();
            GsonParser gparser = new GsonParser();
            gparser.elementLoopParser(element, this);
        }
        return tknlist;
    }

    public ParmGenToken fetchNameValue(String name, int fcnt, AppValue.TokenTypeNames _tokentype) {
        if (element != null) {
            if (map == null) {
                parseJSON2Token();
            }
            if (map != null) {
                ParmGenTokenKey tkey = new ParmGenTokenKey(_tokentype, name, fcnt);
                if (map.containsKey(tkey)) {
                    ParmGenTokenValue tval = map.get(tkey);
                    ParmGenToken tkn = new ParmGenToken(tkey, tval);
                    return tkn;
                }
            }
        }
        return null;
    }

    @Override
    @SuppressWarnings("fallthrough")
    public boolean receiver(
            GsonIterator git, GsonParser.EventType etype, String keyname, Object value, int level) {
        String val = "";
        int fcnt = 0;
        String URL = "";
        ParmGenToken tkn = null;

        switch (etype) {
            case START_OBJECT:
                break;
            case END_OBJECT:
                break;
            case START_ARRAY:
                break;
            case END_ARRAY:
                break;
            case BOOLEAN:
                break;
            case NUMBER:
                if (value instanceof Number) {
                    Number n = (Number) value;
                    val = n.toString();
                }
            case STRING:
                if (value instanceof String) {
                    val = (String) value;
                }
                fcnt = 0;
                if (samenamehash.containsKey(keyname)) {
                    fcnt = samenamehash.get(keyname) + 1;
                }
                samenamehash.put(keyname, fcnt);
                tkn =
                        new ParmGenToken(
                                AppValue.TokenTypeNames.JSON, URL, keyname, val, false, fcnt);
                tknlist.add(tkn);
                map.put(tkn.getTokenKey(), tkn.getTokenValue());
                break;
            case NULL:
                break;
            default:
                break;
        }

        return true;
    }

    @Override
    public ParmGenGSONDecoder clone() {

        try {
            ParmGenGSONDecoder nobj = (ParmGenGSONDecoder) super.clone();
            nobj.init(this.jsondata);
            // List<ParmGenToken> tknlist = null;
            nobj.tknlist = ListDeepCopy.listDeepCopyParmGenToken(this.tknlist);
            // HashMap<String, Integer> samenamehash = null;
            nobj.samenamehash = this.samenamehash != null ? new HashMap<>(this.samenamehash) : null;
            // HashMap<ParmGenTokenKey, ParmGenTokenValue> map = null;
            nobj.map = HashMapDeepCopy.hashMapDeepCopyParmGenHashMapSuper(this.map);

            return nobj;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(ParmGenGSONDecoder.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }
}
