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
import java.util.*;
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
// FetchResponse
//

class FetchResponseVal implements DeepClone {
    //

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    // ====================== copy per thread members begin ===============
    // Key: String token  int toStepNo Val: distance = responseStepNo - currentStepNo
    private Map<ParmGenTokenKey, Integer> distances;

    private ParmGenTrackKeyPerThread trackkeys;
    // ====================== copy per thread members end =================

    //
    FetchResponseVal() {
        init();
    }

    /**
     * this function<br>
     * for internal use<br>
     */
    private void init() {

        // pattern = "<AuthUpload>(?:.|\r|\n|\t)*?<password>([a-zA-Z0-9]+)</password>";
        allocLocVal();

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
    String getLocVal(UUID k, ParmGenTokenKey tk, int currentStepNo, int toStepNo, AppValue ap) {
        String rval = null;
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam != null) {

            // String v = locarray[r][c];
            // int responseStepNo = responseStepNos[r][c];

            String v = tkparam.getValue(ap);
            int responseStepNo = tkparam.getResponseStepNo();

            if (toStepNo >= 0) {
                if (currentStepNo == toStepNo) {
                    rval = v;
                } else if (toStepNo == EnvironmentVariables.TOSTEPANY) {
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
                        distances.put(tk, Integer.valueOf(newdistance));
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
            int currentStepNo, int fromStepNo, String val, boolean overwrite, AppValue av) {
        UUID k = av.getTrackKey();
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam == null) { // if tkparam has No exist, then create tkparam with new unique key
            // key
            tkparam = trackkeys.create(k);
        }

        String cachedval = tkparam.getValue(null);
        if (val != null && (!val.isEmpty() || val.isEmpty() && av.isReplaceZeroSize())) {
            if (cachedval == null) {
                tkparam.setValue(val);
            } else if (overwrite == true) {
                tkparam.setValue(val);
            }
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

    /**
     * update conditional parameter is valid or not
     *
     * @param av
     * @param b
     */
    void updateCond(AppValue av, boolean b) {
        UUID k = av.getTrackKey();
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam == null) { // if tkparam has No exist, then create tkparam with new unique key
            // key
            tkparam = trackkeys.create(k);
        }
        tkparam.setCondValid(b);
        if (!b) {
            tkparam.rollBackValue();
        } else {
            tkparam.overWriteOldValue();
        }
    }

    boolean getCondValid(AppValue av) {
        UUID k = av.getTrackKey();
        ParmGenTrackingParam tkparam = trackkeys.get(k);
        if (tkparam != null) {
            return tkparam.getCondValid();
        }
        return false;
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
            ParmGenMacroTrace pmt,
            String url,
            PResponse presponse,
            int r,
            int c,
            boolean overwrite,
            AppValue av) {
        int currentStepNo = pmt.getStepNo();
        int fromStepNo = av.getFromStepNo();
        String name = av.getToken();
        AppValue.TokenTypeNames _tokentype = av.getTokenType();
        String comments = "";
        if (urlmatch(av, url)) {
            if (_tokentype == AppValue.TokenTypeNames.LOCATION) {
                ParmGenToken tkn = presponse.fetchNameValue(name, _tokentype, 0);
                if (tkn != null) {
                    ParmGenTokenValue tval = tkn.getTokenValue();
                    if (tval != null) { // value値nullは追跡しない
                        String matchval = tval.getValue();
                        if (matchval
                                != null) { // matchval !=null or matchval.isEmpty() is acceptable.
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "*****FETCHRESPONSE header r,c/ header: value"
                                                + r
                                                + ","
                                                + c
                                                + " => "
                                                + matchval;
                            } else {
                                comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getHeaderSucceeded.text"),
                                        new Object[] {pmt.getStepNo(), "Location", matchval});
                            }
                            printlog(comments);
                            pmt.addComments(comments);
                            setLocVal(currentStepNo, fromStepNo, matchval, overwrite, av);
                            return true;
                        }
                    } else {
                        if (LOGGER4J.isDebugEnabled()) {
                            comments =
                                    "xxxxxIGNORED FETCHRESPONSE header r,c/ header: value"
                                            + r
                                            + ","
                                            + c
                                            + " => null";

                        } else {
                            comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getHeaderFailed.text"),
                                    new Object[] {pmt.getStepNo(), "Location"});
                        }
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
                        printlog("Exception matcher：" + e.toString());
                    }
                    if (matcher.find()) {
                        int gcnt = matcher.groupCount();
                        String matchval = null;
                        for (int n = 0; n < gcnt; n++) {
                            matchval = matcher.group(n + 1);
                        }

                        if (matchval
                                != null) { // matchval != null or matchval.isEmpty() is acceptable.
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "*****FETCHRESPONSE header r,c/ header: value"
                                                + r
                                                + ","
                                                + c
                                                + "/"
                                                + hval
                                                + " => "
                                                + matchval;
                            } else {
                                comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getHeaderSucceeded.text"),
                                        new Object[] {pmt.getStepNo(), hval, matchval});
                            }
                            printlog(comments);
                            pmt.addComments(comments);
                            setLocVal(currentStepNo, fromStepNo, matchval, overwrite, av);
                            return true;
                        } else {
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "xxxxxIGNORED FETCHRESPONSE header r,c/ header: value"
                                                + r
                                                + ","
                                                + c
                                                + "/"
                                                + hval
                                                + " => null";

                            } else {
                                comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getHeaderFailed.text"),
                                        new Object[] {pmt.getStepNo(), hval});
                            }
                            printlog(comments);
                            pmt.addComments(comments);
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
            ParmGenMacroTrace pmt,
            String url,
            PResponse presponse,
            int r,
            int c,
            boolean overwrite,
            boolean autotrack,
            AppValue av)
            throws UnsupportedEncodingException {
        int currentStepNo = pmt.getStepNo();
        int fromStepNo = av.getFromStepNo();
        int fcnt = av.getResRegexPos();
        String name = av.getToken();
        boolean _uencode = av.isUrlEncode();
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
                    LOGGER4J.warn(comments);
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
                        if (_uencode == true && !ParmGenUtil.isURLencoded(matchval)) {
                            String venc = matchval;
                            try {
                                venc =
                                        URLEncoder.encode(
                                                matchval,
                                                presponse.getPageEnc().getIANACharsetName());
                            } catch (UnsupportedEncodingException e) {
                                // NOP
                            }
                            matchval = venc;
                        }
                        String ONETIMEPASSWD = matchval.replaceAll(",", "%2C");
                        String comments = "";

                        if (ONETIMEPASSWD
                                != null) { // this variable !=null or isEmpty() is acceptable.

                            setLocVal(currentStepNo, fromStepNo, ONETIMEPASSWD, overwrite, av);
                            if (LOGGER4J.isDebugEnabled()) {
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
                            } else {
                                comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getTokenSucceeded.text"),
                                        new Object[] {pmt.getStepNo(), name, matchval, "Response"});
                            }
                            printlog(comments);
                            pmt.addComments(comments);
                            return true;
                        } else {
                            if (LOGGER4J.isDebugEnabled()) {
                                comments =
                                        "xxxxxx FAILED FETCHRESPONSE body r,c:"
                                                + r
                                                + ","
                                                + c
                                                + ": "
                                                + name
                                                + "="
                                                + "null";

                            } else {
                                comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getTokenFailed.text"),
                                        new Object[] {pmt.getStepNo(), name, "is null", "Response"});
                            }
                            LOGGER4J.warn(comments);
                            pmt.addComments(comments);
                        }
                    } else {
                        String comments = "";
                        if (LOGGER4J.isDebugEnabled()) {
                            comments =
                                    "xxxxxx FAILED FETCHRESPONSE body r,c:"
                                            + r
                                            + ","
                                            + c
                                            + ": "
                                            + name
                                            + "="
                                            + "null";

                        } else {
                            comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getTokenFailed.text"),
                                    new Object[] {pmt.getStepNo(), name, "is null", "Response"});
                        }
                        LOGGER4J.warn(comments);
                        pmt.addComments(comments);
                    }
                } else {
                    String comments = "";
                    if (LOGGER4J.isDebugEnabled()) {
                        comments =
                                "xxxxxx FAILED FETCHRESPONSE body r,c:"
                                        + r
                                        + ","
                                        + c
                                        + ": "
                                        + name
                                        + "="
                                        + "null";

                    } else {
                        comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getTokenFailed.text"),
                                new Object[] {pmt.getStepNo(), name, "No matched regex[" + av.getresRegex() + "]", "Response"});
                    }
                    LOGGER4J.warn(comments);
                    pmt.addComments(comments);
                }
            } else { // extract parameter from parse response
                if (autotrack) {
                    // ParmGenParser parser = new ParmGenParser(body);
                    // ParmGenToken tkn = parser.fetchNameValue(name, fcnt,
                    // _tokentype);
                    ParmGenToken tkn = presponse.fetchNameValue(name, _tokentype, fcnt);
                    if (tkn != null) {
                        ParmGenTokenValue tval = tkn.getTokenValue();
                        if (tval != null) {
                            String v = tval.getValue();
                            if (v != null) { // this variable != null or isEmpty() is acceptable.

                                if (_uencode == true && !ParmGenUtil.isURLencoded(v)) {
                                    String venc = v;
                                    try {
                                        venc =
                                                URLEncoder.encode(
                                                        v,
                                                        presponse
                                                                .getPageEnc()
                                                                .getIANACharsetName());
                                    } catch (UnsupportedEncodingException e) {
                                        // NOP
                                    }
                                    v = venc;
                                }
                                String ONETIMEPASSWD = v.replaceAll(",", "%2C");

                                setLocVal(currentStepNo, fromStepNo, ONETIMEPASSWD, overwrite, av);
                                String comments = "";
                                if (LOGGER4J.isDebugEnabled()) {
                                    comments =
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
                                } else {
                                    comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getTokenSucceeded.text"),
                                            new Object[] {pmt.getStepNo(), name, v, "Response"});
                                }
                                printlog(comments);
                                pmt.addComments(comments);
                                return true;
                            } else {
                                String comments = "";
                                if (LOGGER4J.isDebugEnabled()) {
                                     comments =
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

                                } else {
                                    comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getTokenFailed.text"),
                                            new Object[] {pmt.getStepNo(), name, "is null" , "Response"});
                                }
                                LOGGER4J.warn(comments);
                                pmt.addComments(comments);
                            }
                        }
                    } else {
                        String comments = "";
                        if (LOGGER4J.isDebugEnabled()) {
                            comments =
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

                        } else {
                            comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getTokenFailed.text"),
                                    new Object[] {pmt.getStepNo(), name, "not found", "Response"});
                        }
                        LOGGER4J.warn(comments);
                        pmt.addComments(comments);
                    }
                }
            }
        }
        return false;
    }

    boolean reqbodymatch(
            ParmGenMacroTrace pmt,
            AppValue av,
            String url,
            PRequest prequest,
            int r,
            int c,
            boolean overwrite) {
        int currentStepNo = pmt.getStepNo();
        int fromStepNo = av.getFromStepNo();
        int fcnt = av.getResRegexPos();
        String name = av.getToken();
        String comments = "";
        if (urlmatch(av, url)) {
            ArrayList<String[]> namelist = prequest.getBodyParams();
            Iterator<String[]> it = namelist.iterator();
            while (it.hasNext()) {
                String[] nv = it.next();
                if (name.equals(nv[0])) {
                    if (nv.length > 1
                            && nv[1] != null) { // this variable is != null or isEmpty() is
                        // acceptable
                        if (LOGGER4J.isDebugEnabled()) {
                            comments =
                                    "******FETCH REQUEST body r,c: name=value:"
                                            + r
                                            + ","
                                            + c
                                            + ": "
                                            + nv[0]
                                            + "="
                                            + nv[1];
                        } else {
                            comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getTokenSucceeded.text"),
                                    new Object[] {pmt.getStepNo(), nv[0], nv[1], "Request"});
                        }
                        printlog(comments);
                        pmt.addComments(comments);
                        setLocVal(currentStepNo, fromStepNo, nv[1], overwrite, av);
                        return true;
                    } else {
                        if (LOGGER4J.isDebugEnabled()) {
                            comments =
                                    "xxxxxFAILED FETCH REQUEST body r,c: name=value:"
                                            + r
                                            + ","
                                            + c
                                            + ": "
                                            + nv[0]
                                            + "=null";

                        } else {
                            comments = java.text.MessageFormat.format(bundle.getString("FetchResponseVal.getTokenFailed.text"),
                                    new Object[] {pmt.getStepNo(), nv[0], "Request"});
                        }
                        LOGGER4J.warn(comments);
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
