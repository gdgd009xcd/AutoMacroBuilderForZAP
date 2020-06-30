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

import java.util.Map.Entry;

public class PResponse extends ParseHTTPHeaders {
    private ParmGenHashMap map = null;
    private ParmGenParser htmlparser = null;
    private ParmGenGSONDecoder jsonparser = null;
    // PResponse(){
    //	super();
    // }

    public PResponse(byte[] bin, Encode _pageenc) {
        super(bin, _pageenc);
        map = null;
        htmlparser = null;
        jsonparser = null;
    }

    // Location headerのパラメータ取得
    public <T> InterfaceCollection<T> getLocationTokens(InterfaceCollection<T> tklist) {
        String locheader = getHeader("Location");

        if (locheader != null) {
            String[] nvpairs = locheader.split("[?&]");
            String url = nvpairs[0];
            for (String tnv : nvpairs) {
                String[] nvp = tnv.split("=");
                String name = nvp[0];
                String value = new String("");
                if (nvp.length > 1) {
                    value = nvp[1];

                    if (name != null && name.length() > 0 && value != null) {
                        tklist.addToken(
                                AppValue.TokenTypeNames.LOCATION, url, name, value, false, 0);
                    }
                }
            }
            if (tklist != null && tklist.size() > 0) {
                return tklist;
            }
        }
        return null;
    }

    public ParmGenToken fetchNameValue(String name, AppValue.TokenTypeNames _tokentype, int fcnt) {
        if (map == null) {
            map = new ParmGenHashMap();
            InterfaceCollection<Entry<ParmGenTokenKey, ParmGenTokenValue>> ic =
                    getLocationTokens(map);
            // String subtype = getContent_Subtype();
            switch (_tokentype) {
                case JSON:
                    jsonparser = new ParmGenGSONDecoder(body);
                    break;
                default:
                    htmlparser = new ParmGenParser(body);
                    break;
            }
            /**
             * if(subtype!=null&&subtype.toLowerCase().equals("json")){ jsonparser = new
             * ParmGenJSONDecoder(body); }else{ htmlparser = new ParmGenParser(body); }*
             */
        } else {
            switch (_tokentype) {
                case JSON:
                    if (jsonparser == null) {
                        jsonparser = new ParmGenGSONDecoder(body);
                    }
                    break;
                default:
                    if (htmlparser == null) {
                        htmlparser = new ParmGenParser(body);
                    }
                    break;
            }
        }
        ParmGenTokenKey tkey = new ParmGenTokenKey(_tokentype, name, fcnt);
        ParmGenTokenValue tval = map.get(tkey);
        if (tval != null) {
            return new ParmGenToken(tkey, tval);
        }
        switch (_tokentype) {
            case JSON:
                if (jsonparser != null) {
                    return jsonparser.fetchNameValue(name, fcnt, _tokentype);
                }
                break;
            default:
                if (htmlparser != null) {
                    return htmlparser.fetchNameValue(name, fcnt, _tokentype);
                }
                break;
        }

        return null;
    }

    public PResponse clone() {
        PResponse nobj = (PResponse) super.clone();
        // private ParmGenHashMap map = null;
        nobj.map = this.map != null ? this.map.clone() : null;
        // private ParmGenParser htmlparser = null;
        nobj.htmlparser = this.htmlparser != null ? this.htmlparser.clone() : null;
        // private ParmGenGSONDecoder jsonparser =null;
        nobj.jsonparser = this.jsonparser != null ? this.jsonparser.clone() : null;

        return nobj;
    }
}
