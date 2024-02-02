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
import java.util.HashMap;
import java.util.Map;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

/** @author tms783 */
public class ParmGenParser implements DeepClone {

    final private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    // get the factory
    String htmltext;
    Document doc;
    Elements elems;
    Map<ParmGenTokenKey, ParmGenTokenValue> map;
    Map<ParmGenTokenKey, ParmGenTokenValue> defmap; // T_DEFAULT
    // target tags: input|A|HREF|META
    // private static String tagSelector = "input,a[href],form[action],textarea,meta";
    private static String tagSelector = "[name],a[href],form[action]";

    private void init() {
        htmltext = null;
        doc = null;
        elems = null;
        map = null;
        defmap = null;
    }

    // tracking token parser
    public ParmGenParser(String htmltext) {
        setup(htmltext);
    }

    private void setup(String htmltext) {
        init();

        this.htmltext = htmltext;
        Document doc = null;
        Elements elems = null;

        try {
            doc = Jsoup.parse(htmltext);
            // elems =
            // doc.select("input[type=hidden],input[type=text],input[type=tel],input[type=url],
            // input[type=email],
            // input[type=search],input[type=number],input[type=email],a[href],form[action],textarea");//tag which has name attributes, href , form, textarea
            elems = doc.select(tagSelector);

        } catch (Exception e) {
            // TODO Auto-generated catch block
            LOGGER4J.error(e.getMessage(), e);
            doc = null;
            elems = null;
        }

        this.doc = doc;
        this.elems = elems;
        //elemsprint();
    }

    void elemsprint() {
        for (Element vtag : elems) {
            String n = vtag.attr("name");
            String v = vtag.attr("value");
            String h = vtag.attr("href");
            String content = vtag.attr("content");
            if (vtag.tagName().toLowerCase().equals("input")) { // <input
                LOGGER4J.debug(
                        "<" + vtag.tagName() + " name=\"" + n + "\" value=\"" + v + "\">");
            } else if (vtag.tagName().toLowerCase().equals("a")) { // <A
                LOGGER4J.debug("<" + vtag.tagName() + " href=\"" + h + "\">");

            } else if (vtag.tagName().toLowerCase().equals("meta")) {
                LOGGER4J.debug((ParmGenUtil.isTokenValue(content) ? "Token":"") + "<" + vtag.tagName() + " name=\"" + n + "\" content=\"" + content + "\">");
            } else {
                LOGGER4J.debug("<" + vtag.tagName() + "\">");
            }
        }
    }

    private ArrayList<ParmGenToken> getParmGenTokens(
            Element vtag, HashMap<String, Integer> namepos) {
        String[] nv = null;
        ParmGenToken tk = null;
        ArrayList<ParmGenToken> tklist = new ArrayList<ParmGenToken>();
        String lowerTagName = vtag.tagName().toLowerCase();
        String nameAttribute = vtag.attr("name");
        if (lowerTagName.equals("input")) { // <input
            String v = vtag.attr("value");
            String t = vtag.attr("type");
            // name attribute in input tag.
            String n = nameAttribute;
            if (n.isEmpty()) {
                n = null;
            }
            if (n != null) {
                // count if same name is exist
                int npos = 0;
                if (namepos.containsKey(n)) {
                    npos = namepos.get(n);
                    npos++;
                }
                namepos.put(n, npos);
                AppValue.TokenTypeNames ttype = AppValue.TokenTypeNames.INPUT;
                if (t != null) {
                    if (t.toLowerCase().equals("text")) {
                        ttype = AppValue.TokenTypeNames.TEXT;
                    }
                }
                tk = new ParmGenToken(ttype, "", n, v, false, npos);
                tklist.add(tk);
            }
        } else if (lowerTagName.equals("meta")) { // <meta
            String v = vtag.attr("content");
            // name attribute in input tag.
            String n = nameAttribute;
            if (n.isEmpty()) {
                n = null;
            }
            if (n != null) {
                // count if same name is exist
                int npos = 0;
                if (namepos.containsKey(n)) {
                    npos = namepos.get(n);
                    npos++;
                }
                namepos.put(n, npos);
                AppValue.TokenTypeNames ttype = AppValue.TokenTypeNames.META;
                tk = new ParmGenToken(ttype, "", n, v, false, npos);
                tklist.add(tk);
            }
        } else if (lowerTagName.equals("a")) { // <A
            String h = vtag.attr("href");
            // extract GET(query) parameters from href attribute.
            // ?name=value&....
            if (h != null) {
                String[] nvpairs = h.split("[&?]|amp;");
                String url = nvpairs[0];
                for (String tnv : nvpairs) {
                    String[] nvp = tnv.split("=");
                    String name = nvp[0];
                    String value = new String("");
                    if (nvp.length > 1) {
                        value = nvp[1];

                        if (name != null && name.length() > 0 && value != null) {
                            // count if same name is exist
                            int npos = 0;
                            if (namepos.containsKey(name)) {
                                npos = namepos.get(name);
                                npos++;
                            }
                            namepos.put(name, npos);
                            tk =
                                    new ParmGenToken(
                                            AppValue.TokenTypeNames.HREF,
                                            url,
                                            name,
                                            value,
                                            false,
                                            npos);
                            tklist.add(tk);
                        }
                    }
                }
            }
        } else if (lowerTagName.equals("form")) { // <form
            String h = vtag.attr("action");
            // extract GET(query) parameters from action attribute
            // ?name=value&....
            if (h != null) {
                String[] nvpairs = h.split("[&?]|amp;");
                String url = nvpairs[0];
                for (String tnv : nvpairs) {
                    String[] nvp = tnv.split("=");
                    String name = nvp[0];
                    String value = new String("");
                    if (nvp.length > 1) {
                        value = nvp[1];

                        if (name != null && name.length() > 0 && value != null) {
                            // count if same name is exist
                            int npos = 0;
                            if (namepos.containsKey(name)) {
                                npos = namepos.get(name);
                                npos++;
                            }
                            namepos.put(name, npos);
                            tk =
                                    new ParmGenToken(
                                            AppValue.TokenTypeNames.ACTION,
                                            url,
                                            name,
                                            value,
                                            false,
                                            npos);
                            tklist.add(tk);
                        }
                    }
                }
            }
        } else if (lowerTagName.equals("textarea")) { // <textarea
            String n = nameAttribute;
            String v = vtag.html();
            String t = vtag.attr("type");
            // name attribute in textarea tag
            if (n.isEmpty()) {
                n = null;
            }
            if (n != null) {
                // count if same name is exist
                int npos = 0;
                if (namepos.containsKey(n)) {
                    npos = namepos.get(n);
                    npos++;
                }
                namepos.put(n, npos);
                AppValue.TokenTypeNames ttype = AppValue.TokenTypeNames.TEXTAREA;

                tk = new ParmGenToken(ttype, "", n, v, false, npos);
                tklist.add(tk);
            }
        }
        return tklist;
    }

    /**
     * get ParmGenToken list from response
     *
     * @return
     */
    public ArrayList<ParmGenToken> getNameValues() {

        HashMap<String, Integer> namepos = new HashMap<String, Integer>();
        ArrayList<ParmGenToken> lst = new ArrayList<ParmGenToken>();

        try {

            for (Element vtag : elems) {

                ArrayList<ParmGenToken> tklist = getParmGenTokens(vtag, namepos);
                lst.addAll(tklist);
            }

        } catch (Exception e) {
            // TODO Auto-generated catch block
            LOGGER4J.error(e.getMessage(), e);
        }

        return lst;
    }

    /**
     * Gets the ParmGenToken that matches the specified parameters.
     * @param name
     * @param fcnt
     * @param _tokentype
     * @return
     */
    public ParmGenToken fetchNameValue(String name, int fcnt, AppValue.TokenTypeNames _tokentype) {
        if (name == null) return null; // name nullは不可。
        ParmGenTokenKey tkey = null;
        HashMap<String, Integer> namepos = new HashMap<String, Integer>();

        if (map == null) {
            map = new HashMap<ParmGenTokenKey, ParmGenTokenValue>();
            defmap = new HashMap<ParmGenTokenKey, ParmGenTokenValue>();
            for (Element vtag : elems) {
                ArrayList<ParmGenToken> tklist = getParmGenTokens(vtag, namepos);
                for (ParmGenToken tkn : tklist) {
                    tkey = tkn.getTokenKey();

                    map.put(tkey, tkn.getTokenValue());

                    ParmGenTokenKey dkey = new ParmGenTokenKey(tkey); // copy

                    dkey.setTokenType(AppValue.TokenTypeNames.DEFAULT);

                    defmap.put(dkey, tkn.getTokenValue());
                }
            }
        }
        Map<ParmGenTokenKey, ParmGenTokenValue> selectmap = map;
        if (_tokentype == AppValue.TokenTypeNames.DEFAULT) {
            selectmap = defmap;
        }

        tkey = new ParmGenTokenKey(_tokentype, name, fcnt);
        ParmGenTokenValue tval = selectmap.get(tkey);
        if (tval != null) {
            return new ParmGenToken(tkey, tval);
        } else if (fcnt > 0) {
            while (fcnt-- > 0) {
                tkey = new ParmGenTokenKey(_tokentype, name, fcnt);
                tval = selectmap.get(tkey);
                if (tval != null) {
                    return new ParmGenToken(tkey, tval);
                }
            }
        }
        return null;
    }

    @Override
    public ParmGenParser clone() {
        try {
            ParmGenParser nobj = (ParmGenParser) super.clone();
            nobj.setup(this.htmltext);
            nobj.map = HashMapDeepCopy.hashMapDeepCopyParmGenHashMapSuper(this.map);
            nobj.defmap = HashMapDeepCopy.hashMapDeepCopyParmGenHashMapSuper(this.defmap);
            return nobj;
        } catch (CloneNotSupportedException ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }

        return null;
    }
}
