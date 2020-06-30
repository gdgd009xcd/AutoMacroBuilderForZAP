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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;

// <?xml version="1.0" encoding="utf-8"?>
// <AuthUpload>
//	<codeResult>0</codeResult>
//	<password>eUnknfj73OFBrMenCfFh</password>
// </AuthUpload>

//
// class variable
//
// FetchResponse初期化
//

class FetchResponseVal implements DeepClone {
    //

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    Encode _enc = null;

    // ====================== copy per thread members begin ===============
    // Key: String token  int toStepNo Val: distance = responseStepNo - currentStepNo
    private HashMap<ParmGenTokenKey, Integer> distances;

    private ParmGenTrackKeyPerThread trackkeys;
    // ====================== copy per thread members end =================

    private ParmGenMacroTrace pmt;

    //
    FetchResponseVal(ParmGenMacroTrace pmt) {
        init(pmt);
    }

    /**
     * for internal use
     *
     * @param pmt
     */
    private void init(ParmGenMacroTrace pmt) {
        this.pmt = pmt;

        // pattern = "<AuthUpload>(?:.|\r|\n|\t)*?<password>([a-zA-Z0-9]+)</password>";
        allocLocVal();

        _enc = ParmVars.enc;
        if (_enc == null) {
            _enc = Encode.UTF_8;
        }
        initLocVal();
    }

    private String strrowcol(int r, int c) {
        return Integer.toString(r) + "," + Integer.toString(c);
    }

    private void allocLocVal() {
        trackkeys = new ParmGenTrackKeyPerThread();
        distances = new HashMap<ParmGenTokenKey, Integer>();
    }

    private void initLocVal() {
        clearCachedLocVal();
        if (distances != null) {
            distances.clear();
        }
    }

    public void clearCachedLocVal() {
        if (trackkeys != null) trackkeys.clear();
    }

    public void clearDistances() {
        if (distances != null) {
            distances.clear();
        }
    }

    // this function affects AppParmsIni.T_TRACK only..
    /**
     * get response's tracking token from TrackJarFactory
     *
     * @param k (unique key) int
     * @param tk ParmGenTokenKey
     * @param currentStepNo int
     * @param toStepNo int
     * @return token value String
     */
    String getLocVal(UUID k, ParmGenTokenKey tk, int currentStepNo, int toStepNo) {
        String rval = null;
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam != null) {

            // String v = locarray[r][c];
            // int responseStepNo = responseStepNos[r][c];

            String v = tkparam.getValue();
            int responseStepNo = tkparam.getResponseStepNo();

            if (toStepNo >= 0) {
                if (currentStepNo == toStepNo) {
                    rval = v;
                } else if (toStepNo == ParmVars.TOSTEPANY) {
                    rval = v;
                }
            }

            if (rval == null) {
                // ParmVars.plog.debuglog(0, "????????????getLocVal rval==null toStepNo:" + toStepNo
                // + "currentStepNo=" + currentStepNo );
            }

            if (tk != null && distances != null) {
                if (rval != null) {
                    int newdistance = currentStepNo - responseStepNo; // from to distance
                    Integer intobj = distances.get(tk);

                    if (intobj != null) {
                        int prevdistance = intobj.intValue();
                        if (prevdistance >= 0) {
                            if (prevdistance < newdistance) {
                                rval = null;
                            }
                        }
                    }
                    if (rval != null) {
                        distances.put(tk, new Integer(newdistance));
                    }
                }
            }
        }
        if (rval == null) {
            // ParmVars.plog.debuglog(0, "?!???!??????getLocVal rval==null toStepNo:" + toStepNo +
            // "currentStepNo=" + currentStepNo );
        }
        return rval;
    }

    private int getStepNo(UUID k) {
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam != null) {
            // return responseStepNos[r][c];
            return tkparam.getResponseStepNo();
        }
        return -1;
    }

    /** set response's tracking token to TrackJarFactory */
    private UUID setLocVal(
            UUID k, int currentStepNo, int fromStepNo, String val, boolean overwrite) {
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam == null) { // if tkparam has No exist, then create tkparam with new unique key
            // key
            tkparam = trackkeys.create(k);
        }

        String cachedval = tkparam.getValue();
        if (cachedval == null) {
            tkparam.setValue(val);
        } else if (overwrite == true) {
            tkparam.setValue(val);
        }

        if (fromStepNo < 0
                || currentStepNo == fromStepNo) { // if fromStepNo <0 : token value from any
            // or
            // currentStepNo == fromStepNo : token value from fromStepNo
            // then set ResponseStepNo
            // setStepNo(currentStepNo, r, c);
            tkparam.setResponseStepNo(currentStepNo);
        }

        trackkeys.put(k, tkparam);

        return k;
    }

    // void copyLocVal(int fr, int fc, int tr, int tc){
    //    if(isValid(fr,fc) && isValid(tr,tc)){
    //	String v = locarray[fr][fc];
    //        int stepno = responseStepNos[fr][fc];
    //	setLocVal(stepno, -1, tr, tc, v, true);
    //    }
    // }

    void printlog(String v) {
        LOGGER4J.info(v);
    }

    //
    // header match
    //
    boolean headermatch(
            int currentStepNo,
            int fromStepNo,
            String url,
            PResponse presponse,
            int r,
            int c,
            boolean overwrite,
            String name,
            AppValue av) {
        AppValue.TokenTypeNames _tokentype = av.getTokenType();
        String comments = "";
        if (urlmatch(av, url)) {
            if (_tokentype == AppValue.TokenTypeNames.LOCATION) {
                ParmGenToken tkn = presponse.fetchNameValue(name, _tokentype, 0);
                if (tkn != null) {
                    ParmGenTokenValue tval = tkn.getTokenValue();
                    if (tval != null) { // value値nullは追跡しない
                        String matchval = tval.getValue();
                        if (matchval != null && !matchval.isEmpty()) {
                            comments =
                                    "*****FETCHRESPONSE header r,c/ header: value"
                                            + r
                                            + ","
                                            + c
                                            + " => "
                                            + matchval;
                            printlog(comments);
                            pmt.addComments(comments);
                            setLocVal(
                                    av.getTrackKey(),
                                    currentStepNo,
                                    fromStepNo,
                                    matchval,
                                    overwrite);
                            return true;
                        }
                    } else {
                        comments =
                                "xxxxxIGNORED FETCHRESPONSE header r,c/ header: value"
                                        + r
                                        + ","
                                        + c
                                        + " => null";
                        printlog(comments);
                        pmt.addComments(comments);
                    }
                }
            } else if (av.getPattern_resRegex() != null) {
                //
                int size = presponse.getHeadersCnt();
                for (int i = 0; i < size; i++) {
                    // String nvName = (nv[i]).getName();
                    // String nvValue = (nv[i]).getValue();
                    // String hval = nvName + ": " + nvValue;
                    String hval = presponse.getHeaderLine(i);
                    Matcher matcher = null;
                    try {
                        matcher = av.getPattern_resRegex().matcher(hval);
                    } catch (Exception e) {
                        printlog("matcher例外：" + e.toString());
                    }
                    if (matcher.find()) {
                        int gcnt = matcher.groupCount();
                        String matchval = null;
                        for (int n = 0; n < gcnt; n++) {
                            matchval = matcher.group(n + 1);
                        }

                        if (matchval != null) {
                            if (!matchval.isEmpty()) { // value値nullは追跡しない
                                comments =
                                        "*****FETCHRESPONSE header r,c/ header: value"
                                                + r
                                                + ","
                                                + c
                                                + "/"
                                                + hval
                                                + " => "
                                                + matchval;
                                printlog(comments);
                                pmt.addComments(comments);
                                setLocVal(
                                        av.getTrackKey(),
                                        currentStepNo,
                                        fromStepNo,
                                        matchval,
                                        overwrite);
                                return true;
                            } else {
                                comments =
                                        "xxxxxIGNORED FETCHRESPONSE header r,c/ header: value"
                                                + r
                                                + ","
                                                + c
                                                + "/"
                                                + hval
                                                + " => null";
                                printlog(comments);
                                pmt.addComments(comments);
                            }
                        }
                    }
                }
            }
        }
        return false;
    }
    //
    // body match
    //
    boolean bodymatch(
            int currentStepNo,
            int fromStepNo,
            String url,
            PResponse presponse,
            int r,
            int c,
            boolean overwrite,
            boolean autotrack,
            AppValue av,
            int fcnt,
            String name,
            boolean _uencode)
            throws UnsupportedEncodingException {
        AppValue.TokenTypeNames _tokentype = av.getTokenType();
        if (urlmatch(av, url)) {

            Matcher matcher = null;

            if (av.getPattern_resRegex() != null
                    && av.getresRegex() != null
                    && !av.getresRegex().isEmpty()) { // extracted by regex
                String message = presponse.getMessage();

                try {
                    matcher = av.getPattern_resRegex().matcher(message);
                } catch (Exception e) {
                    String comments =
                            "xxxxx EXCEPTION FETCHRESPONSE r,c:"
                                    + r
                                    + ","
                                    + c
                                    + ": "
                                    + name
                                    + " 正規表現["
                                    + av.getresRegex()
                                    + "] 例外："
                                    + e.toString();
                    printlog(comments);
                    pmt.addComments(comments);
                    matcher = null;
                }

                if (matcher != null && matcher.find()) {
                    int gcnt = matcher.groupCount();
                    String matchval = null;
                    for (int n = 0; n < gcnt; n++) {
                        matchval = matcher.group(n + 1);
                    }

                    if (matchval != null) {
                        switch (av.getResEncodeType()) {
                            case JSON:
                                ParmGenGSONDecoder jdec = new ParmGenGSONDecoder(null);
                                matchval = jdec.decodeStringValue(matchval);
                                break;
                            default:
                                break;
                        }
                        if (_uencode == true) {
                            String venc = matchval;
                            try {
                                venc =
                                        URLEncoder.encode(
                                                matchval, ParmVars.enc.getIANACharsetName());
                            } catch (UnsupportedEncodingException e) {
                                // NOP
                            }
                            matchval = venc;
                        }
                        String ONETIMEPASSWD = matchval.replaceAll(",", "%2C");
                        String comments = "";

                        if (ONETIMEPASSWD != null && !ONETIMEPASSWD.isEmpty()) { // value値nullは追跡しない

                            setLocVal(
                                    av.getTrackKey(),
                                    currentStepNo,
                                    fromStepNo,
                                    ONETIMEPASSWD,
                                    overwrite);
                            comments =
                                    "*****FETCHRESPONSE body key/r,c:"
                                            + av.getTrackKey()
                                            + "/"
                                            + r
                                            + ","
                                            + c
                                            + ": "
                                            + name
                                            + "="
                                            + ONETIMEPASSWD;
                            printlog(comments);
                            pmt.addComments(comments);
                            return true;
                        } else {
                            comments =
                                    "xxxxxx FAILED FETCHRESPONSE body r,c:"
                                            + r
                                            + ","
                                            + c
                                            + ": "
                                            + name
                                            + "="
                                            + "null";
                            printlog(comments);
                            pmt.addComments(comments);
                        }
                    }
                }
            } else { // extract parameter from parse response
                String body = presponse.getBody();

                if (autotrack) {
                    // ParmGenParser parser = new ParmGenParser(body);
                    // ParmGenToken tkn = parser.fetchNameValue(name, fcnt,
                    // _tokentype);
                    ParmGenToken tkn = presponse.fetchNameValue(name, _tokentype, fcnt);
                    if (tkn != null) {
                        ParmGenTokenValue tval = tkn.getTokenValue();
                        if (tval != null) {
                            String v = tval.getValue();
                            if (v != null && !v.isEmpty()) { // value null値は追跡しない。

                                if (_uencode == true) {
                                    String venc = v;
                                    try {
                                        venc =
                                                URLEncoder.encode(
                                                        v, ParmVars.enc.getIANACharsetName());
                                    } catch (UnsupportedEncodingException e) {
                                        // NOP
                                    }
                                    v = venc;
                                }
                                String ONETIMEPASSWD = v.replaceAll(",", "%2C");

                                setLocVal(
                                        av.getTrackKey(),
                                        currentStepNo,
                                        fromStepNo,
                                        ONETIMEPASSWD,
                                        overwrite);
                                String comments =
                                        "*****FETCHRESPONSE auto track body key/r,c,p:"
                                                + av.getTrackKey()
                                                + "/"
                                                + r
                                                + ","
                                                + c
                                                + ","
                                                + fcnt
                                                + ": "
                                                + name
                                                + "="
                                                + v;
                                printlog(comments);
                                pmt.addComments(comments);
                                return true;
                            } else {
                                String comments =
                                        "xxxxx FAILED FETCHRESPONSE auto track body r,c,p:"
                                                + r
                                                + ","
                                                + c
                                                + ","
                                                + fcnt
                                                + ": "
                                                + name
                                                + "="
                                                + "null";
                                printlog(comments);
                                pmt.addComments(comments);
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    boolean reqbodymatch(
            AppValue av,
            int currentStepNo,
            int fromStepNo,
            String url,
            PRequest prequest,
            int r,
            int c,
            boolean overwrite,
            int fcnt,
            String name) {
        String comments = "";
        if (urlmatch(av, url)) {
            ArrayList<String[]> namelist = prequest.getBodyParams();
            Iterator<String[]> it = namelist.iterator();
            while (it.hasNext()) {
                String[] nv = it.next();
                if (name.equals(nv[0])) {
                    if (nv.length > 1 && nv[1] != null && !nv[1].isEmpty()) { // value値nullは追跡しない
                        comments =
                                "******FETCH REQUEST body r,c: name=value:"
                                        + r
                                        + ","
                                        + c
                                        + ": "
                                        + nv[0]
                                        + "="
                                        + nv[1];
                        printlog(comments);
                        pmt.addComments(comments);
                        setLocVal(av.getTrackKey(), currentStepNo, fromStepNo, nv[1], overwrite);
                        return true;
                    } else {
                        comments =
                                "xxxxxFAILED FETCH REQUEST body r,c: name=value:"
                                        + r
                                        + ","
                                        + c
                                        + ": "
                                        + nv[0]
                                        + "=null";
                        printlog(comments);
                        pmt.addComments(comments);
                    }
                }
            }
        }
        return false;
    }
    //
    // URL match
    //
    boolean urlmatch(AppValue av, String url) {

        try {
            if (av.getPattern_resURL() != null) {
                Matcher matcher = av.getPattern_resURL().matcher(url);
                if (matcher.find()) {
                    // printlog("*****FETCHRESPONSE URL match:" + url);
                    LOGGER4J.debug(" FETCH RESPONSE URL matched:[" + url + "]");
                    return true;
                }
                // printlog("urlmatch find failed:r,c,url, rmax=" + strrowcol(r,c) + "," + url + ","
                // + Integer.toString(rmax));

            }
        } catch (Exception e) {
            printlog("matcher例外：" + e.toString());
        }
        return false;
    }

    @Override
    public FetchResponseVal clone() {
        FetchResponseVal nobj = null;
        try {
            nobj = (FetchResponseVal) super.clone();
            nobj._enc = this._enc;
            nobj.pmt = this.pmt;
            nobj.distances =
                    HashMapDeepCopy.hashMapDeepCopyParmGenTokenKeyKIntegerV(this.distances);
            nobj.trackkeys = this.trackkeys.clone();
            return nobj;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(FetchResponseVal.class.getName()).log(Level.SEVERE, null, ex);
        }
        return nobj;
    }
}

// Request request = connection.getRequest();
// Response response = connection.getResponse();
// String url = request.getURL().toString();
// global.Location.clearResponse();

// for TEST
// if(global.Location.bodymatch(url, response, 0, 0, true)){//
// }

// ２）指定したポジションr,cのレスポンスマッチを指定
// カートＩＤ 削除
// if(global.Location.bodymatch(url, response, 0, 0, false)){
//	global.Location.copyLocVal(0, 0, 0, 1, false);
//	global.Location.copyLocVal(0, 0, 0, 2, false);
//	global.Location.copyLocVal(0, 0, 0, 4, false);
//	global.Location.copyLocVal(0, 0, 1, 0, false);
//	global.Location.copyLocVal(0, 0, 1, 1, false);
// }

// みんなのわんこ Set-Cookie取得
// if(global.Location.headermatch(url, response, 1, 9, false)){//LocationヘッダーのあるレスポンスのCookieを取得
//	if(global.Location.headermatch(url, response, 1, 0, false)){
//	}
//	if(global.Location.headermatch(url, response, 1, 1, false)){
//	}
// }

// if(global.Location.bodymatch(url, response, 0, 0, true)){//
// }

// global.Location.clearResponse();
// request = null;
// response = null;
// url = null;
// connection = null;
