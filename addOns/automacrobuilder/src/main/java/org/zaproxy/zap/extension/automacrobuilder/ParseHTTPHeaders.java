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

import static org.zaproxy.zap.extension.automacrobuilder.HashMapDeepCopy.hashMapDeepCopyStrKStrV;

import java.net.HttpCookie;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

//
// HTTP request/response parser
//

class ParseHTTPHeaders implements DeepClone {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private static int MAXLENOFHTTPHEADER = 10000;
    Pattern valueregex;
    // Pattern formdataregex;
    String formdataheader;
    String formdatacontenttype;
    String formdatafooter;
    Pattern formdataheaderregex;
    Pattern formdatacontenttyperegex;
    Pattern formdatafooterregex;
    private String[] nv = null; // temporary work parameter. no need copy in constructor.
    boolean crlf;
    String method;
    String url;
    boolean isSSL; // ==true then ssl
    String path;
    String path_pref_url;
    String protocol;
    String status;
    String reason;
    String host;
    int port;
    public ArrayList<String> pathparams;
    public ArrayList<String[]> cookieparams;
    private Map<String, String> hashqueryparams;
    private Map<String, String> hashbodyparams;
    private ArrayList<String[]> queryparams;
    private ArrayList<String[]> bodyparams;
    ArrayList<String[]> headers;
    Map<String, ParmGenHeader> hkeyUpper_Headers = null; // key is UpperCase
    private ArrayList<String> setcookieheaders; // Set-Cookie headers
    // REMOVE private HashMap<String,ArrayList<String[]>> set_cookieparams;//String Key, ArrayList
    // name=value pair
    String content_type; // Content-Type: image/gif
    String content_subtype;
    String charset;
    String boundary;
    int parsedheaderlength;
    boolean isHeaderModified; // ==true parsedheaderlengthは再計算。
    private int content_length;
    boolean formdata;

    private String bodystring; // encode = pageenc. maybe body's binary data != bytebody, because
    // pageencoding
    // affect it.
    byte[] bytebody; // bytes of contents without headers.
    ParmGenBinUtil binbody = null;
    String iso8859bodyString = null;
    // form-data 以外は、ページエンコードでOK。
    // form-dataのみ、セパレータ単位でエンコードする処理が必要。
    private Encode pageenc = Encode.ISO_8859_1; // default

    String message; // when update method(Ex. setXXX) is called, then this value must set to null;
    private boolean isrequest; // == true - request, false - response

    final HeaderPattern[] headerpatterns = {
        // Authorization: Bearer token68
        //         token68: alpha,digit, "-._~+/", "=" (RFC 6750 2.1 base64token )
        new HeaderPattern(
                "Authorization",
                // String.format("xxxx (Bearer) %s xxxx", tokenvalue)
                "[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]:[\\r\\n\\t ]*([bB][eE][aA][rR][eE][rR])[\\r\\n\\t ]*%s(?:[\\r\\n\\t ])*",
                // String.format("xxxx %s (value) xxxx", tokenvalue)
                "[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]:[\\r\\n\\t ]*%s[\\r\\n\\t ]*([a-zA-Z0-9\\-\\._~\\+/]+\\=*)(?:[\\r\\n\\t ])*",
                ParmGenRequestTokenKey.RequestParamType.Header,
                ParmGenRequestTokenKey.RequestParamSubType.Bearer),
        // Cookie: token  =  value
        // token: any char except ctrls and delimiters「"(" | ")" | "<" | ">" | "@" | "," | ";" | ":"
        // | "\" | <">| "/" | "[" | "]" | "?" | "="| "{" | "}" | SP | HT」
        // ==[^\cA-\cZ()<>@,;:\\"/[]?={} ]
        // value: cookie-octet or "cookie-octet"
        //        cookie-octet: any char except 「CTL, SP, DQUOTE, ",", ";", "\"」 ==
        // [\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]
        // RFC 6265 4.1.1 Set-Cookie header syntax , 4.2.1 Cookie header syntax
        new HeaderPattern(
                "Cookie",
                // String.format("xxxx (name)=%s xxxx", tokenvalue)
                "[cC][oO][oO][kK][iI][eE]:[\\r\\n\\t ]*(?:.*;[ ]+)*([^\\cA-\\cZ()<>@,;:\\\\\"/\\[\\]?={} ]+)[\\r\\n\\t ]*=[\\r\\n\\t ]*\"?%s\"?(?:[\\r\\n\\t ]|;)*",
                // String.format("xxxx %s=(value) xxxx", tokenname)
                "[cC][oO][oO][kK][iI][eE]:[\\r\\n\\t ]*(?:.*;[ ]+)*%s[\\r\\n\\t ]*=[\\r\\n\\t ]*\"?([\\x21\\x23-\\x2B\\x2D-\\x3A\\x3C-\\x5B\\x5D-\\x7E]+)\"?(?:[\\r\\n\\t ]|;)*",
                ParmGenRequestTokenKey.RequestParamType.Header,
                ParmGenRequestTokenKey.RequestParamSubType.Cookie),
    };

    public static final String CUSTOM_THREAD_ID_HEADERNAME = "X-PARMGEN-THREAD-HEADER";
    public static final String CUSTOM_PARAMS_HEADERNAME = "X-PARMGEN-PARAMS-HEADER";

    private void init() {
        bodystring = null;
        pageenc = Encode.ISO_8859_1;
        binbody = null;
        iso8859bodyString = null;
        valueregex = ParmGenUtil.Pattern_compile("(([^\r\n:]*):{0,1}[ \t]*([^\r\n]*))(\r\n)");
        // formdataregex = ParmGenUtil.Pattern_compile("-{4,}[a-zA-Z0-9]+(?:\r\n)(?:[A-Z].*
        // name=\"(.*?)\".*(?:\r\n))(?:[A-Z].*(?:\r\n)){0,}(?:\r\n)((?:.|\r|\n)*?)(?:\r\n)-{4,}[a-zA-Z0-9]+");
        formdataheader = "(?:[A-Z].* name=\"(.*?)\".*(?:\r\n))(?:[A-Z].*(?:\r\n)){0,}(?:\r\n)";
        formdatacontenttype =
                "(?:[A-Z].* name=\".*?\".*(?:\r|\n|\r\n))(?:Content-Type:[ \t]*([a-zA-Z\\.\\-0-9/]*)(?:\r|\n|\r\n)){1}(?:\r|\n|\r\n)";
        formdatafooter = "(?:\r\n)";
        nv = null;
        isSSL = false;
        crlf = false;
        isrequest = false;
        message = null;
        pathparams = new ArrayList<String>();
        cookieparams = new ArrayList<String[]>();
        // REMOVE set_cookieparams = new HashMap<String,ArrayList<String[]>>();
        setcookieheaders = new ArrayList<>();
        charset = "";
        content_type = "";
        content_subtype = "";
        queryparams = new ArrayList<String[]>();
        hashqueryparams = new HashMap<String, String>();
        hkeyUpper_Headers = new HashMap<String, ParmGenHeader>();
        bodyparams = null;
        hashbodyparams = null;
        boundary = null;
        formdata = false;
        content_length = -1;
        bytebody = null;
        path_pref_url = "";
        parsedheaderlength = 0;
        isHeaderModified = true;
    }

    ParseHTTPHeaders(byte[] _binmessage, Encode _penc) {
        construct("", 0, false, _binmessage, _penc);
    }

    ParseHTTPHeaders(String _h, int _p, boolean _isssl, byte[] _binmessage, Encode _penc) {
        construct(_h, _p, _isssl, _binmessage, _penc);
    }

    ParseHTTPHeaders(ParseHTTPHeaders pheaders) {
        deepcopy(pheaders);
    }

    private void deepcopy(ParseHTTPHeaders pheaders) {
        init();
        valueregex = pheaders.valueregex;

        formdataheader = pheaders.formdataheader;
        formdatacontenttype = pheaders.formdatacontenttype;
        formdatafooter = pheaders.formdatafooter;
        formdataheaderregex = pheaders.formdataheaderregex;
        formdatacontenttyperegex = pheaders.formdatacontenttyperegex;
        formdatafooterregex = pheaders.formdatafooterregex;
        nv = null; // tempoary work parameter. no need copy.
        crlf = pheaders.crlf;
        method = pheaders.method;
        url = pheaders.url;
        isSSL = pheaders.isSSL;
        path = pheaders.path;
        path_pref_url = pheaders.path_pref_url;
        protocol = pheaders.protocol;
        status = pheaders.status;
        reason = pheaders.reason;
        host = pheaders.host;
        port = pheaders.port;
        pathparams = new ArrayList<>(pheaders.pathparams);
        cookieparams = ParmGenUtil.copyStringArrayList(pheaders.cookieparams);
        hashqueryparams = hashMapDeepCopyStrKStrV(pheaders.hashqueryparams);
        hashbodyparams = hashMapDeepCopyStrKStrV(pheaders.hashbodyparams);
        queryparams = ParmGenUtil.copyStringArrayList(pheaders.queryparams);
        bodyparams = ParmGenUtil.copyStringArrayList(pheaders.bodyparams);
        headers = ParmGenUtil.copyStringArrayList(pheaders.headers);
        hkeyUpper_Headers =
                HashMapDeepCopy.hashMapDeepCopyStrKParmGenHeaderV(pheaders.hkeyUpper_Headers);
        setcookieheaders = new ArrayList<>(pheaders.setcookieheaders);
        // REMOVE set_cookieparams = copyset_cookieparams(pheaders.set_cookieparams);
        content_type = pheaders.content_type;
        content_subtype = pheaders.content_subtype;
        charset = pheaders.charset;
        boundary = pheaders.boundary;
        parsedheaderlength = pheaders.parsedheaderlength;
        isHeaderModified = pheaders.isHeaderModified;
        content_length = pheaders.content_length;
        formdata = pheaders.formdata;
        bodystring = pheaders.bodystring;
        bytebody = ParmGenUtil.copyBytes(pheaders.bytebody);
        binbody = pheaders.binbody != null ? new ParmGenBinUtil(pheaders.binbody.getBytes()) : null;
        iso8859bodyString = pheaders.iso8859bodyString;
        pageenc = pheaders.pageenc;
        message = pheaders.message;
        isrequest = pheaders.isrequest;
    }

    private String httpMessageString(byte[] _binmessage, Encode pageenc) {

        this.pageenc = pageenc != null ? pageenc : Encode.ISO_8859_1;
        String httpmessage = null;

        try {
            httpmessage = new String(_binmessage, pageenc.getIANACharset());
        } catch (Exception ex) {
            this.pageenc = Encode.ISO_8859_1; // falling default enc
            try {
                httpmessage = new String(_binmessage, this.pageenc.getIANACharset());
            } catch (Exception ex1) {
                Logger.getLogger(ParseHTTPHeaders.class.getName()).log(Level.SEVERE, null, ex1);
                httpmessage = null;
            }
        }
        return httpmessage;
    }

    public void construct(String _h, int _p, boolean _isssl, byte[] _binmessage, Encode _penc) {
        init();
        int separatorPos =
                ParmGenUtil.indexOf(
                        _binmessage,
                        "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1),
                        0,
                        MAXLENOFHTTPHEADER);
        if (separatorPos > 0) {
            byte[] headerBytes = new byte[separatorPos];
            System.arraycopy(_binmessage, 0, headerBytes, 0, separatorPos);
            String headerString = new String(headerBytes, StandardCharsets.ISO_8859_1) + "\r\n\r\n";
            ParseHttpContentType pContType = new ParseHttpContentType(headerString);
            if (pContType.hasContentTypeHeader()) {
                String charsetName = pContType.getCharSetName();
                if (charsetName != null && !charsetName.isEmpty()) {
                    _penc = Encode.getEnum(charsetName);
                }
            }
        }

        String httpmessage = httpMessageString(_binmessage, _penc);

        if (httpmessage != null) {
            ArrayList<String[]> dummy = Parse(httpmessage);
            int hlen = getParsedHeaderLength();
            ParmGenBinUtil warray = new ParmGenBinUtil(_binmessage);
            if (_binmessage != null && hlen < warray.length()) {
                byte[] _body = warray.subBytes(hlen);
                setBody(_body);
            }
            if (isRequest()) {
                // parse後に明示的に設定。
                host = _h;
                port = _p;
                isSSL = _isssl;
            }
            // ParmVars.plog.debuglog(0, "construct isRequest/host/port/SSL"
            // +(isRequest()?"REQUEST": "RESPONSE")+ host + "/" + port + "/" +
            // (isSSL?"SSL":"NOSSL"));
        }
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public boolean isSSL() {
        return isSSL;
    }

    public String getPathPrefURL() {
        return path_pref_url;
    }

    public boolean isFormData() {
        return formdata;
    }

    private int getStringBodyLength() {
        if (bodystring != null) {
            try {
                int blen = bodystring.getBytes(pageenc.getIANACharset()).length;
                return blen;
            } catch (Exception e) {
                ParmVars.plog.printException(e);
            }
        }
        return 0;
    }

    public int getHeaderLength() {
        String h = getHeaderOnly();
        if (h != null) {
            try {
                int blen = h.getBytes(pageenc.getIANACharset()).length;
                return blen;
            } catch (Exception e) {
                ParmVars.plog.printException(e);
            }
        }
        return 0;
    }

    public int getParsedHeaderLength() {
        if (isHeaderModified) {
            // 再計算
            String headerdata = getHeaderOnly();
            parsedheaderlength = headerdata.length();
            isHeaderModified = false;
        }
        return parsedheaderlength;
    }

    public void setSSL(boolean _ssl) {
        isSSL = _ssl;
    }

    public void setPort(int _p) {
        port = _p;
    }

    private ArrayList<String[]> Parse(String httpmessage) { // request or response
        parsedheaderlength = 0;
        Matcher m = valueregex.matcher(httpmessage);
        String name = "";
        String value = "";
        String rec = "";
        crlf = false;
        headers = new ArrayList<String[]>();
        boolean frec = true;
        message = null;
        boundary = null;
        while (m.find()) {
            name = "";
            value = "";
            rec = "";
            int gcnt = m.groupCount();
            if (gcnt > 1) {
                rec = m.group(1);
            }
            if (gcnt > 2) {
                name = m.group(2);
            }
            if (gcnt > 3) {
                value = m.group(3);
            }
            if (name.length() <= 0
                    && value.length() <= 0) { // found crlfcrlf　separator between header and body.
                crlf = true;
                int epos = m.end(gcnt);
                parsedheaderlength = epos;
                bodystring = httpmessage.substring(epos);
                break;
            } else {
                if (frec) { // start-line
                    nv = rec.split("[ \t]+", 3);
                    // request nv[0] method nv[1] url nv[2] protocol
                    if (nv.length > 2) {
                        method = nv[0];

                        String lowerline = method.toLowerCase();

                        if (lowerline.startsWith("http")) { // response
                            isrequest = false;
                            protocol = nv[0];
                            status = nv[1];
                            reason = nv[2];
                            // REMOVE set_cookieparams.clear();
                            setcookieheaders.clear();
                        } else { // request;
                            isrequest = true;
                            method = nv[0];
                            url = nv[1];
                            String[] parms = url.split("[?&]");
                            if (parms.length > 0) {
                                path = parms[0];
                                String lowerpath = path.toLowerCase();
                                if (lowerpath.startsWith("http")) {
                                    path_pref_url = "http";
                                    isSSL = false;
                                    if (lowerpath.startsWith("https")) {
                                        path_pref_url = "https";
                                        isSSL = true;
                                    }
                                    String[] actualpaths = path.split("[/]");
                                    String resultpath = "/";
                                    for (int k = 0; k < actualpaths.length; k++) {
                                        if (k > 2) {
                                            resultpath +=
                                                    (resultpath.equals("/") ? "" : "/")
                                                            + actualpaths[k];
                                        }
                                    }
                                    path = resultpath;
                                }
                                if (!path.isEmpty()) {
                                    String[] pathlist = path.split("[/]");
                                    for (int j = 1; j < pathlist.length; j++) {
                                        pathparams.add(pathlist[j]);
                                    }
                                }
                            }
                            if (parms.length > 1) {
                                for (int i = 1; i < parms.length; i++) {
                                    String[] nv = parms[i].trim().split("=");
                                    String[] nvpair = new String[2];
                                    if (nv.length > 0) {
                                        nvpair[0] = nv[0]; // nv[0] is not null
                                    } else {
                                        nvpair[0] = "";
                                    }
                                    if (nv.length > 1) {
                                        nvpair[1] = nv[1]; // nv[1] is not null
                                    } else {
                                        nvpair[1] = "";
                                    }
                                    queryparams.add(nvpair);
                                    hashqueryparams.put(
                                            decodedParamName(nvpair[0], pageenc), nvpair[1]);
                                }
                            }
                            protocol = nv[2];
                        }
                    }
                    frec = false;
                } else { // headers
                    nv = new String[2];
                    nv[0] = new String(name.trim());
                    nv[1] = new String(value.trim());
                    int hi = headers.size();
                    headers.add(nv);
                    ParmGenHeader pgheader = new ParmGenHeader(hi, nv[0], nv[1]);
                    ParmGenHeader existheader = hkeyUpper_Headers.get(pgheader.getKeyUpper());
                    if (existheader != null) {
                        existheader.addValue(hi, nv[1]);
                        hkeyUpper_Headers.put(existheader.getKeyUpper(), existheader);
                    } else {
                        hkeyUpper_Headers.put(pgheader.getKeyUpper(), pgheader);
                    }
                    port = 80; // default
                    if (nv[0].toLowerCase().startsWith("host")) {
                        String[] hasport = nv[1].split("[:]");
                        if (hasport.length > 1) {
                            port = Integer.parseInt(hasport[1]);
                        }
                        if (hasport.length > 0) {
                            host = hasport[0];
                        }
                    }
                    if (nv[0].toLowerCase().startsWith("content-type")) {
                        String[] types = nv[1].split("[ ;\t]");

                        for (int i = 0; i < types.length; i++) {
                            if (types[i].toLowerCase().startsWith("charset")) {
                                String[] csets = types[i].split("[ \t=]");
                                charset = "";
                                for (String v : csets) {
                                    charset = v;
                                }
                            } else {
                                int slpos = types[i].indexOf("/");
                                if (slpos > 0) { // type/subtype
                                    content_type = types[i].substring(0, slpos).toLowerCase();
                                    if (types[i].length() > slpos + 1) {
                                        content_subtype =
                                                types[i].substring(slpos + 1, types[i].length())
                                                        .toLowerCase();
                                    }
                                } else {
                                    if (types[i].toLowerCase().startsWith("boundary=")) {
                                        String[] boundaries = types[i].split("[=]");
                                        if (boundaries.length > 1) {
                                            boundary = boundaries[1];
                                            formdataheaderregex =
                                                    ParmGenUtil.Pattern_compile(formdataheader);
                                            formdatacontenttyperegex =
                                                    ParmGenUtil.Pattern_compile(
                                                            formdatacontenttype);
                                            formdatafooterregex =
                                                    ParmGenUtil.Pattern_compile(
                                                            formdatafooter + "--" + boundary);
                                            formdata = true;
                                        }
                                    }
                                }
                            }
                        }
                    } else if (nv[0].toLowerCase().startsWith("content-length")) {
                        content_length = Integer.parseInt(nv[1]);
                    } else if (nv[0].toLowerCase().startsWith("cookie")) {
                        String[] cookies = nv[1].split("[\r\n;]");
                        cookieparams.clear();
                        for (int ck = 0; ck < cookies.length; ck++) {
                            String[] cnv = cookies[ck].trim().split("[=]");
                            if (cnv.length > 1) {
                                String[] nvpair = new String[2];
                                nvpair[0] = new String(cnv[0]);
                                nvpair[1] = new String(cnv[1]);
                                cookieparams.add(nvpair);
                            }
                        }
                    } else if (nv[0].toLowerCase().startsWith("set-cookie")) { // レスポンスのSet-Cookie値
                        setcookieheaders.add(nv[1]);
                        /**
                         * ** REMOVE String[] cookies = nv[1].split("[\r\n;]"); String setckey =
                         * null; String setcval = null; ArrayList<String[]> setclist = new
                         * ArrayList<String[]>(); for(int ck = 0; ck < cookies.length; ck++){
                         * String[] cnv = cookies[ck].trim().split("[=]"); String[] nvpair = new
                         * String[2]; if(cnv.length>1){ nvpair[0] = new String(cnv[0]); nvpair[1] =
                         * new String(cnv[1]); if(ck==0){//cookie name=value setckey = nvpair[0];
                         * setcval = nvpair[1]; } setclist.add(nvpair); //ParmVars.plog.debuglog(0,
                         * "Set-Cookie: K[" + setckey + "] " + nvpair[0] + "=" + nvpair[1]);
                         *
                         * <p>}else{ if(cnv[0].toLowerCase().startsWith("httponly")){ nvpair[0] =
                         * new String("httponly"); nvpair[1] = new String(cnv[0]); }else
                         * if(cnv[0].toLowerCase().startsWith("secure")){ nvpair[0] = new
                         * String("secure"); nvpair[1] = new String(cnv[0]); } setclist.add(nvpair);
                         * //ParmVars.plog.debuglog(0, "Set-Cookie: K[" + setckey + "] " + nvpair[0]
                         * + "=" + nvpair[1]); } } if(setckey!=null){
                         * //set_cookieparams.put(setckey, setclist); } **
                         */
                    } else if (nv[0].toLowerCase()
                            .startsWith("authorization")) { // Authorization header
                        if (nv[1].toLowerCase().startsWith("bearer")
                                && nv[1].length() > 8) { // Authorization: Bearer token68
                            // NOP..
                        }
                    }
                }
            }
        }

        isHeaderModified = false;
        return headers;
    }

    public ArrayList<String[]> getQueryParams() {
        return queryparams;
    }

    public ArrayList<String[]> getBodyParams() {
        if (isrequest == true && bodyparams == null) {
            bodyparams = new ArrayList<String[]>();
            hashbodyparams = new HashMap<String, String>();
            if (boundary == null) {
                // application/x-www-form-urlencoded
                String[] parms = bodystring.split("[&]");
                if (parms.length >= 1) {
                    for (int i = 0; i < parms.length; i++) {
                        String[] nv = parms[i].trim().split("=");
                        String[] nvpair = new String[2];
                        if (nv.length > 0 && !nv[0].isEmpty()) {
                            nvpair[0] = new String(nv[0]);
                        } else {
                            nvpair[0] = null;
                        }
                        if (nv.length > 1) {
                            nvpair[1] = new String(nv[1]);
                        } else {
                            nvpair[1] = new String("");
                        }
                        if (nvpair[0] != null) {
                            bodyparams.add(nvpair);
                            hashbodyparams.put(decodedParamName(nvpair[0], pageenc), nvpair[1]);
                        }
                    }
                }
            } else { // multipart/form-data
                boolean lasthyphen = true;
                String parsebody = "\r\n" + bodystring;
                String formvalue = null;
                int bpos = -1;
                int epos = -1;
                int nextbpos = -1;
                Matcher fm = formdatafooterregex.matcher(parsebody);
                while (fm.find()) {
                    if (bpos == -1) {
                        bpos = fm.end();
                        continue;
                    } else {
                        epos = fm.start();
                        nextbpos = fm.end();
                        ParmVars.plog.debuglog(1, "bpos=" + Integer.toString(bpos));
                        ParmVars.plog.debuglog(1, "epos=" + Integer.toString(epos));
                        ParmVars.plog.debuglog(1, "nextbpos=" + Integer.toString(nextbpos));
                    }
                    formvalue = parsebody.substring(bpos, epos); // セパレータ間のデータ（header含む）
                    String dv = formvalue.replaceAll("\r", "<CR>");
                    dv = dv.replaceAll("\n", "<LF>");
                    ParmVars.plog.debuglog(1, dv);
                    Matcher fn = formdataheaderregex.matcher(formvalue);
                    Matcher contentfn = formdatacontenttyperegex.matcher(formvalue);
                    boolean isbinarycontents = false;
                    if (contentfn.find()) {
                        int cnt = contentfn.groupCount();
                        if (cnt > 0) {
                            String contenttype = contentfn.group(1);
                            isbinarycontents = ParmGenUtil.isBinaryMimeContent(contenttype);
                            LOGGER4J.debug(
                                    (isbinarycontents ? "BINARY " : " ")
                                            + "cnt:"
                                            + cnt
                                            + " content-type["
                                            + contenttype
                                            + "]");
                        }
                    }
                    if (fn.find() && !isbinarycontents) {
                        try {
                            String[] nvpair = new String[2];
                            int fgcnt = fn.groupCount();

                            nvpair[0] = new String(fgcnt > 0 ? fn.group(1) : "");

                            nvpair[1] = formvalue.substring(fn.end());
                            nvpair[1] = nvpair[1].replaceAll("\r\n", "(?:\\\\r\\\\n|\\\\n)");
                            nvpair[1] = nvpair[1].replaceAll("\r", "(?:\\\\r|\\\\n)");
                            nvpair[1] = nvpair[1].replaceAll("\n", "(?:\\\\r|\\\\n)");
                            ParmVars.plog.debuglog(1, "name[" + nvpair[0] + "]");
                            if (fgcnt > 0) {
                                bodyparams.add(nvpair);
                                hashbodyparams.put(decodedParamName(nvpair[0], pageenc), nvpair[1]);
                            }
                        } catch (Exception e) {
                            ParmVars.plog.printException(e);
                        }
                    }
                    bpos = nextbpos;
                }
            } //
        }
        return bodyparams;
    }
    //
    // setter
    //
    //
    void setURL(String _url) {
        url = _url;
        message = null;
        isHeaderModified = true;
    }

    void setHeader(int i, String name, String value) {
        String[] nv = new String[2];
        nv[0] = new String(name);
        nv[1] = new String(value);
        headers.set(i, nv);
        updateParmGenHeader(i, nv[0], nv[1]);
        message = null;
        isHeaderModified = true;
    }

    void setHeader(String name, String value) {
        int i = findHeader(name);
        if (i >= 0) {
            setHeader(i, name, value);
        } else { // 追加
            String[] nv = new String[2];
            nv[0] = new String(name);
            nv[1] = new String(value);
            i = headers.size();
            headers.add(nv);
        }
        updateParmGenHeader(i, name, value);
        message = null;
        isHeaderModified = true;
    }

    public void removeHeader(String name) {
        ParmGenHeader phg = getParmGenHeader(name);
        if (phg != null) {
            ListIterator<ParmGenBeen> it = phg.getValuesIter();
            while (it.hasNext()) {
                ParmGenBeen been = it.next();
                headers.remove(been.i);
                it.remove();
            }
            hkeyUpper_Headers.remove(name.toUpperCase());
            message = null;
            isHeaderModified = true;
        }
    }

    void setBody(byte[] _bval) {
        bytebody = _bval;

        if (isrequest) {
            int bl = bytebody != null ? bytebody.length : 0;
            int hl = content_length;
            if (bl != hl) { // actual body length != header's content-length value
                setHeader("Content-Length", Integer.toString(bl));
                content_length = bl;
            }
        }

        try {
            bodystring = new String(bytebody, pageenc.getIANACharset());
        } catch (Exception ex) {
            ParmVars.plog.printException(ex);
        }
        binbody = null;
        message = null;
    }

    void setCookie(String name, String value) {
        int len = cookieparams.size();
        boolean isCookieUpdated = false;

        for (int i = 0; i < len; i++) {
            String[] pair = cookieparams.get(i);
            if (pair[0].equals(name)) {
                // cookie更新
                pair[1] = value;
                cookieparams.set(i, pair);
                isCookieUpdated = true;
                break;
            }
        }
        if (!isCookieUpdated) {
            // cookie追加
            String[] cv = new String[2];
            cv[0] = name;
            cv[1] = value;
            cookieparams.add(cv);
            isCookieUpdated = true;
        }
        // headersのcookieを更新
        Iterator<String[]> it = cookieparams.iterator();
        String cookiedata = "";
        while (it.hasNext()) {
            if (!cookiedata.equals("")) {
                cookiedata += "; ";
            }
            String[] nv = it.next();
            cookiedata += nv[0] + "=" + nv[1];
        }
        setHeader("Cookie", cookiedata);

        message = null;
        isHeaderModified = true;
    }

    boolean setCookies(
            HashMap<CookieKey, ArrayList<CookiePathValue>> cookiemap, boolean replaceCookie) {
        if (cookiemap == null || cookiemap.size() == 0) {
            return false;
        }
        ListIterator<String[]> it = cookieparams.listIterator(); // Request's cookie headers
        String domain = host;
        String cookiedata = "";
        boolean cookiemodified = false;
        while (it.hasNext()) {
            if (!cookiedata.equals("")) {
                cookiedata += "; ";
            }
            String[] nv = it.next();
            CookieKey ckey = new CookieKey(domain, nv[0]);
            ArrayList<CookiePathValue> cpvlist = cookiemap.get(ckey);
            LOGGER4J.debug(
                    "setCookies: domain:"
                            + domain
                            + " name="
                            + nv[0]
                            + " cpvlist.size="
                            + (cpvlist == null ? "null" : cpvlist.size()));

            if (cpvlist != null) {
                // pathプロパティの短いものから長いものの順で、Cookie値を設定。
                // Set cookie values  after arrange path property in ascending order(from short path
                // "/" to long path "/aaa/bbb").
                Collections.sort(cpvlist, new PathComparator<>().reversed());
                ListIterator<CookiePathValue> itv = cpvlist.listIterator();
                Boolean cpvlist_changed = false;
                while (itv.hasNext()) {
                    CookiePathValue cpv = itv.next();
                    String _cpath = cpv.getPath();
                    String _cvalue = cpv.getValue();
                    String pathval = path;
                    if (!pathval.endsWith("/")) {
                        pathval += "/";
                    }
                    if (pathval.startsWith(_cpath)) {
                        int len = nv[1].length() - _cvalue.length();
                        String tail = "";
                        if (!replaceCookie) {
                            if (len > 0) {
                                tail = nv[1].substring(_cvalue.length());
                            }
                        }
                        nv[1] = _cvalue + tail;
                        it.set(nv);
                        itv.remove();
                        cpvlist_changed = true;
                        cookiemodified = true;
                        break;
                    }
                }
                if (cpvlist_changed) {
                    if (cpvlist.size() > 0) {
                        cookiemap.put(ckey, cpvlist);
                    } else {
                        cookiemap.remove(ckey);
                    }
                }
            }
            if (nv[1] != null && nv[1].toLowerCase().startsWith("deleted")) {
                it.remove();
            } else {
                cookiedata += nv[0] + "=" + nv[1];
            }
        }
        if (cookiemodified) {
            setHeader("Cookie", cookiedata);
            LOGGER4J.debug("Cookie: " + cookiedata);
            isHeaderModified = true;
            message = null;
            int l = getParsedHeaderLength();
            return true;
        }
        return false;
    }

    public boolean setCookiesFromCookieMan(ParmGenCookieManager cookieman) {
        List<HttpCookie> hcookies = cookieman.get(host, path, isSSL);
        return setCookies(hcookies);
    }

    private boolean setCookies(List<HttpCookie> hcookies) {
        HashMap<CookieKey, ArrayList<CookiePathValue>> cookiemap =
                new HashMap<CookieKey, ArrayList<CookiePathValue>>();
        for (HttpCookie cookie : hcookies) {
            String domain = cookie.getDomain();
            if (domain == null) domain = "";
            String name = cookie.getName();
            if (name == null) name = "";
            String path = cookie.getPath();
            if (path == null) path = "";
            String value = cookie.getValue();
            if (value == null) value = "";
            CookieKey cikey = new CookieKey(domain, name);
            CookiePathValue cpvalue = new CookiePathValue(path, value);
            ArrayList<CookiePathValue> cpvlist = cookiemap.get(cikey);
            if (cpvlist == null) {
                cpvlist = new ArrayList<CookiePathValue>();
            }

            cpvlist.add(cpvalue);

            cookiemap.put(cikey, cpvlist);
        }

        return setCookies(cookiemap, true);
    }

    boolean removeCookies(ArrayList<String> names) {
        Iterator<String[]> it = cookieparams.iterator();
        String cookiedata = "";
        boolean cookie_deleted = false;
        boolean isdeleted = false;
        if (names != null && names.size() > 0) {
            while (it.hasNext()) {
                if (!cookiedata.equals("") && !isdeleted) {
                    cookiedata += "; ";
                }
                String[] nv = it.next();

                isdeleted = false;
                for (int i = 0; i < names.size(); i++) {
                    if (nv[0].equals(names.get(i))) { // Cookie name is case sensitive..
                        // ParmVars.plog.debuglog(0, "removeCookie: " + nv[0] );
                        it.remove();
                        cookie_deleted = true;
                        isdeleted = true;
                        break;
                    }
                }
                if (!isdeleted) {
                    cookiedata += nv[0] + "=" + nv[1];
                }
            }
            if (cookie_deleted) { // 削除された
                if (cookiedata.isEmpty()) {
                    removeHeader("Cookie");
                } else {
                    setHeader("Cookie", cookiedata);
                }
                isHeaderModified = true;
                message = null;
                int l = getParsedHeaderLength();
            }
        }
        return cookie_deleted;
    }

    //
    // getter
    //
    //
    public String getMethod() {
        return method;
    }

    public String getURL() {
        return url;
    }

    public String getPath() {
        return path;
    }

    /**
     * get body string without header. this is encoded enc.
     *
     * @return
     */
    public String getBodyStringWithoutHeader() {
        return bodystring;
    }

    boolean isRequest() {
        return isrequest;
    }

    String getStartline() {
        if (isrequest) {
            return method + " " + url + " " + protocol;
        }
        return protocol + " " + status + " " + reason;
    }

    public String getStatus() {
        return status;
    }

    /**
     * get whole(header+body) message string.
     *
     * @return
     */
    public String getMessage() { // return String in pageenc encoding

        if (message != null) {
            return message;
        }

        // content-length must set byte size!!
        /*
        String clengthheader = getHeader("Content-Length");
        if (clengthheader == null || clengthheader.isEmpty()) {
            byte[] cb = getBodyBytes();
            int l = cb != null ? cb.length: 0;
            setHeader("Content-Length", Integer.toString(l));
        }
        */

        StringBuilder sb = new StringBuilder();

        sb.append(getStartline() + "\r\n");
        for (int i = 0; i < headers.size(); i++) {
            sb.append(getHeaderLine(i) + "\r\n");
        }
        sb.append("\r\n");
        sb.append(getBodyStringWithoutHeader());
        // ParmVars.plog.debuglog(0, "getMessage sb.len=" + sb.length());
        message = new String(sb);
        // ParmVars.plog.debuglog(0, "getMessage done.");

        return message;
    }

    /**
     * get Byte message ( header + CRLF + body )
     *
     * @return
     */
    public byte[] getByteMessage() {

        if (bytebody != null) { // byte[] bytebodyから
            setHeader("Content-Length", Integer.toString(bytebody.length));
            StringBuilder sb = new StringBuilder();

            sb.append(getStartline() + "\r\n");
            for (int i = 0; i < headers.size(); i++) {
                sb.append(getHeaderLine(i) + "\r\n");
            }
            sb.append("\r\n");

            String headerpart = new String(sb);
            ParmGenBinUtil rawmessage = new ParmGenBinUtil();
            try {
                rawmessage = new ParmGenBinUtil(headerpart.getBytes(pageenc.getIANACharset()));
                if (bytebody != null) {
                    rawmessage.concat(bytebody);
                }
            } catch (Exception ex) {
                ParmVars.plog.printException(ex);
            }

            return rawmessage.getBytes();
        } else { // String bodyから
            String strmess = getMessage();
            try {
                byte[] binmess = strmess.getBytes(pageenc.getIANACharset());
                return binmess;
            } catch (Exception e) {
                ParmVars.plog.printException(e);
            }
        }
        return null;
    }

    public String getHeaderOnly() {
        StringBuilder sb = new StringBuilder();

        sb.append(getStartline() + "\r\n");
        for (int i = 0; i < headers.size(); i++) {
            sb.append(getHeaderLine(i) + "\r\n");
        }
        sb.append("\r\n");
        return new String(sb);
    }

    //
    // headerの数
    //
    int getHeadersCnt() {
        return headers.size();
    }

    String getHeaderLine(int i) {
        String result = null;
        if (i >= 0 && headers.size() > i) {
            @SuppressWarnings("LocalVariableHidesMemberVariable")
            String[] nv = headers.get(i);
            result = nv[0] + ": " + nv[1];
        }
        return result;
    }

    public String getHeader(String name) {
        int i = findHeader(name);
        if (i >= 0) {
            @SuppressWarnings("LocalVariableHidesMemberVariable")
            String[] nv = headers.get(i);
            return nv[1];
        }
        return null;
    }

    String[] getHeaderNV(int i) {
        if (headers != null && i >= 0 && headers.size() > i) {
            return headers.get(i);
        }
        return null;
    }

    public ArrayList<String[]> getHeaders() {
        return headers;
    }

    // RFC 2616 - "Hypertext Transfer Protocol -- HTTP/1.1", Section 4.2, "Message Headers":
    // Each header field consists of a name followed by a colon (":") and the field value. Field
    // names are case-insensitive.
    int findHeader(String name) {
        Iterator<String[]> ite = headers.iterator();
        int i = 0;
        while (ite.hasNext()) {
            String[] obj = ite.next();
            if (obj instanceof String[]) {
                nv = obj;
                if (name.toLowerCase().equals(nv[0].toLowerCase())) {
                    return i;
                }
            }
            i++;
        }
        return -1;
    }

    ParmGenHeader getParmGenHeader(String name) {
        if (hkeyUpper_Headers != null && name != null) {
            return hkeyUpper_Headers.get(name.toUpperCase());
        }
        return null;
    }

    private void updateParmGenHeader(int i, String name, String value) {
        if (hkeyUpper_Headers != null && name != null) {
            ParmGenHeader phg = getParmGenHeader(name);
            if (phg != null) {
                ListIterator<ParmGenBeen> it = phg.getValuesIter();
                boolean beenupdated = false;
                while (it.hasNext()) {
                    ParmGenBeen been = it.next();
                    if (been.i == i) {
                        been.v = value;
                        it.set(been);
                        beenupdated = true;
                    }
                }
                if (!beenupdated) {
                    phg.addValue(i, value);
                }
                hkeyUpper_Headers.put(phg.getKeyUpper(), phg);
            } else {
                phg = new ParmGenHeader(i, name, value);
                hkeyUpper_Headers.put(phg.getKeyUpper(), phg);
            }
        }
    }

    Map<String, ParmGenHeader> getheadersHash() {
        return hkeyUpper_Headers;
    }

    public String getContent_Type() {
        return content_type;
    }

    String getContent_Subtype() {
        return content_subtype;
    }

    public String getCharset() {
        return charset;
    }

    private boolean isEqualParam(String resname, String reqname) {
        if (resname.equals(reqname)) return true;
        else {
            try {
                String decoded = URLDecoder.decode(reqname, pageenc.getIANACharsetName());
                if (resname.equals(decoded)) return true;
            } catch (Exception ex) {
                Logger.getLogger(ParseHTTPHeaders.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return false;
    }

    public String decodedParamName(String _name, Encode enc) {
        try {
            String decoded = URLDecoder.decode(_name, enc.getIANACharsetName());
            return decoded;
        } catch (Exception ex) {
            Logger.getLogger(ParseHTTPHeaders.class.getName()).log(Level.SEVERE, null, ex);
        }
        return _name;
    }

    // body parameter same name & value
    public boolean hasBodyParam(String pname, String value) {
        if (getBodyParams() != null) {
            for (String[] pair : bodyparams) { // bodyparams
                if (isEqualParam(pname, pair[0]) && isEqualParam(value, pair[1])) return true;
            }
        }
        return false;
    }

    public boolean hasBodyParamName(String pname) {
        if (getBodyParams() != null) {
            for (String[] pair : bodyparams) { // bodyparams
                if (isEqualParam(pname, pair[0])) return true;
            }
        }
        return false;
    }

    public ParmGenRequestToken getRequestBodyToken(String pname) {
        if (getBodyParams() != null) {
            for (String[] pair : bodyparams) { // bodyparams
                if (isEqualParam(pname, pair[0])) {
                    ParmGenRequestTokenKey.RequestParamType rptype =
                            ParmGenRequestTokenKey.RequestParamType.X_www_form_urlencoded;
                    if (isFormData()) {
                        rptype = ParmGenRequestTokenKey.RequestParamType.Form_data;
                    }
                    // ParmGenRequestToken(ParmGenRequestTokenKey.RequestParamType _rptype,
                    // ParmGenRequestTokenKey.RequestParamSubType _subtype,String _name, String
                    // _value, int _fcnt)
                    return new ParmGenRequestToken(
                            rptype,
                            ParmGenRequestTokenKey.RequestParamSubType.Default,
                            pair[0],
                            pair[1],
                            0);
                }
            }
        }
        return null;
    }

    // query parameter same name & value
    public boolean hasQueryParam(String pname, String value) {
        if (queryparams != null) {
            for (String[] pair : queryparams) { // queryparams
                if (isEqualParam(pname, pair[0]) && isEqualParam(value, pair[1])) return true;
            }
        }
        return false;
    }

    public boolean hasQueryParamName(String pname) {
        if (queryparams != null) {
            for (String[] pair : queryparams) { // queryparams
                if (isEqualParam(pname, pair[0])) return true;
            }
        }
        return false;
    }

    public ParmGenRequestToken getRequestQueryToken(String pname) {
        if (queryparams != null) {
            for (String[] pair : queryparams) { // queryparams
                if (isEqualParam(pname, pair[0])) {
                    // ParmGenRequestToken(ParmGenRequestTokenKey.RequestParamType _rptype,
                    // ParmGenRequestTokenKey.RequestParamSubType _subtype,String _name, String
                    // _value, int _fcnt)
                    return new ParmGenRequestToken(
                            ParmGenRequestTokenKey.RequestParamType.Query,
                            ParmGenRequestTokenKey.RequestParamSubType.Default,
                            pair[0],
                            pair[1],
                            0);
                }
            }
        }
        return null;
    }

    public String getQueryParamValue(String _name) {
        if (hashqueryparams != null) {
            return hashqueryparams.get(_name);
        }
        return null;
    }

    public String getBodyParamValue(String _name) {
        if (hashbodyparams == null) {
            getBodyParams();
        }
        return hashbodyparams.get(_name);
    }

    public String getBoundary() {
        if (boundary == null) {
            ParmGenHeader pgh = getParmGenHeader("Content-Type");
            if (pgh != null) {
                ListIterator<ParmGenBeen> it = pgh.getValuesIter();
                if (it != null && it.hasNext()) { // 先頭のヘッダーを取り出す。
                    ParmGenBeen been = it.next();
                    String content_type = been.v;
                    Pattern ctypepattern =
                            ParmGenUtil.Pattern_compile("multipart/form-data;.*?boundary=(.+)$");
                    Matcher ctypematcher = ctypepattern.matcher(content_type);
                    if (ctypematcher.find()) {
                        boundary = ctypematcher.group(1);
                        boundary = "--" + boundary; //
                        return boundary;
                    }
                }
            }
        }
        return null;
    }

    /**
     * get byte of Body contents without headers.
     *
     * @return byte[]
     */
    public byte[] getBodyBytes() {
        if (bytebody != null) {
            return bytebody;
        } else {
            byte[] requestbytes = getByteMessage();
            ParmGenBinUtil warray = new ParmGenBinUtil(requestbytes);
            try {
                // ParmVars.plog.debuglog(1,"request length : " + Integer.toString(warray.length())
                // + "/" + Integer.toString(prequest.getParsedHeaderLength()));
                if (warray.length() > getParsedHeaderLength()) {
                    bytebody = warray.subBytes(getParsedHeaderLength());
                    return bytebody;
                }
            } catch (Exception e) {

            }
        }
        return null;
    }

    public ParmGenBinUtil getBinBody() {
        if (binbody == null) {
            byte[] bdata = getBodyBytes();
            if (bdata != null) {
                binbody = new ParmGenBinUtil(bdata);
            }
        }
        return binbody;
    }

    public String getISO8859BodyString() {
        if (iso8859bodyString == null) {
            byte[] bdata = getBodyBytes();
            if (bdata != null) {

                try {
                    iso8859bodyString = new String(bdata, Encode.ISO_8859_1.getIANACharset());
                } catch (Exception ex) {
                    Logger.getLogger(ParseHTTPHeaders.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }
        return iso8859bodyString;
    }

    public Encode getPageEnc() {
        return pageenc;
    }

    // return Content-Type value : text/html
    public String getContentMimeType() {
        String res_content_type = getContent_Type();
        String res_content_subtype = getContent_Subtype();

        String res_contentMimeType = res_content_type + "/" + res_content_subtype;

        return res_contentMimeType;
    }

    public int getBodyContentLength() {
        if (content_length == -1) {
            byte[] bdata = null;
            bdata = getBodyBytes();
            if (bdata != null) {
                return bdata.length;
            } else {
                // ParmVars.plog.debuglog(0, "getBodyContentLength bdata is null");
            }
        }
        return content_length;
    }

    public List<String> getSetCookieHeaders() {
        return setcookieheaders;
    }

    /**
     * extract request header patterns which has tkval value<br>
     * e.g. cookie: name=tkval<br>
     * Authorization: Bearer tkval
     *
     * @param tkval
     * @return
     */
    public ArrayList<HeaderPattern> hasHeaderMatchedValue(String tkval) {
        //
        ArrayList<HeaderPattern> alist = new ArrayList<>();
        HashMap<Integer, Integer> sameTokens = new HashMap<>();

        for (HeaderPattern hpattern : headerpatterns) {
            ParmGenHeader pgh =
                    getParmGenHeader(hpattern.getUpperHeaderName()); // get same name header
            if (pgh != null) {

                // Authorization: Bearer token68
                // extract token68, then compare it with tkval
                ListIterator<ParmGenBeen> it = pgh.getValuesIter();
                while (it.hasNext()) {
                    HeaderPattern hpattern_copy = new HeaderPattern(hpattern);
                    ParmGenBeen bn = it.next();
                    String headerline = pgh.getName() + ": " + bn.v;
                    Pattern tkname_pattern = hpattern_copy.getTokenName_RegexPattern(tkval);
                    Matcher tkname_matcher = tkname_pattern.matcher(headerline);
                    if (tkname_matcher.find()) {
                        String tokenname = tkname_matcher.group(1);
                        hpattern_copy.setTkName(tokenname);
                        Pattern tkvalue_pattern =
                                hpattern_copy.getTokenValue_RegexPattern(tokenname);
                        Matcher tkvalue_matcher = tkvalue_pattern.matcher(headerline);
                        if (tkvalue_matcher.find()) {
                            String matched_tkvalue = tkvalue_matcher.group(1);
                            if (matched_tkvalue != null && matched_tkvalue.equals(tkval)) {
                                Integer fcnt_obj = sameTokens.get(hpattern_copy.getSameTokenHash());
                                int fcnt = 0;
                                if (fcnt_obj != null) {
                                    fcnt = fcnt_obj;
                                    fcnt++;
                                }
                                sameTokens.put(hpattern_copy.getSameTokenHash(), fcnt);
                                hpattern_copy.setFcnt(fcnt);
                                alist.add(hpattern_copy);
                            }
                        }
                    }
                }
            }
        }
        return alist;
    }

    public void setUUID2CustomHeader(UUID uuid) {
        String v = uuid.toString();

        setHeader(CUSTOM_THREAD_ID_HEADERNAME, v);
    }

    public UUID getUUID5CustomHeader() {
        String v = getHeader(CUSTOM_THREAD_ID_HEADERNAME);
        if (v != null) {
            UUID uuid = UUID.fromString(v);
            return uuid;
        }
        return null;
    }

    public void setParamsCustomHeader(ParmGenMacroTraceParams pmtParams) {
        setHeader(CUSTOM_PARAMS_HEADERNAME, pmtParams.toString());
    }

    public ParmGenMacroTraceParams getParamsCustomHeader() {
        String v = getHeader(CUSTOM_PARAMS_HEADERNAME);
        ParmGenMacroTraceParams pmtParams = null;
        if (v != null) {
            pmtParams = new ParmGenMacroTraceParams(v);
        }

        return pmtParams;
    }

    @Override
    public ParseHTTPHeaders clone() {
        try {
            ParseHTTPHeaders nobj = (ParseHTTPHeaders) super.clone();
            nobj.deepcopy(this);
            return nobj;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(ParseHTTPHeaders.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
