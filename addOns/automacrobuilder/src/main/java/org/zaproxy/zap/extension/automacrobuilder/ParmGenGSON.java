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

import static org.zaproxy.zap.extension.automacrobuilder.ParmVars.JSONFileIANACharsetName;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** @author gdgd009xcd */
public class ParmGenGSON implements GsonParserListener {
    private static org.apache.logging.log4j.Logger logger4j =
            org.apache.logging.log4j.LogManager.getLogger();
    // --loaded values
    private String Version;
    private Encode encodeObsoleteFormatV1; // obsolete. new V2 File format does Not need this.
    private List<String> ExcludeMimeTypes = null;
    private ArrayList<AppParmsIni> rlist;
    private ArrayList<PRequestResponse> ReqResList;
    private int currentrequest;
    private boolean ProxyInScope;
    private boolean IntruderInScope;
    private boolean RepeaterInScope;
    private boolean ScannerInScope;
    // ---------------

    private AppParmsIni aparms;
    private AppValue apv;
    private List<String> JSONSyntaxErrors;
    private List<Exception> ExceptionErrors;
    private int row = 0;
    ParmGenStack<String> astack = null;

    // PRequestResponse gsonObject v1
    // @deprecated
    private GSONSaveObject.GsonPRequestResponse gsonObjectPRequestResponse = null;
    // PRequestResponse gsonObject v2
    private GSONSaveObjectV2.GsonPRequestResponse gsonPRequestResponse = null;

    // current TabIndex
    private int tabIndex;
    // AppParmAndSequence for loading Gson and converting pmt
    public static class AppParmAndSequence {
        public int myPageIndex; // position index of MyPage in PRequestResponse list
        public int currentRequest; // position index of current selected request in PRequestResponse
        public Encode sequenceEncode; // Encode value for entire Sequence of PRequestResponses
        // list
        public List<PRequestResponse> pRequestResponses = null; // RequestResponse sequence list
        public List<AppParmsIni> appParmsIniList = null; // tracking parameter list

        AppParmAndSequence() {
            init();
        }

        public void init() {
            myPageIndex = -1;
            currentRequest = -1;
            sequenceEncode = Encode.UTF_8;
            if (pRequestResponses == null) {
                pRequestResponses = new ArrayList<>();
            } else {
                pRequestResponses.clear();
            }
            if (appParmsIniList == null) {
                appParmsIniList = new ArrayList<>();
            } else {
                appParmsIniList.clear();
            }
        }
    }

    AppParmAndSequence appParmAndSequence = null;
    List<AppParmAndSequence> appParmAndSequenceList = null;

    public ParmGenGSON() {
        astack = new ParmGenStack<String>();
        ProxyInScope = false;
        IntruderInScope = false;
        RepeaterInScope = false;
        ScannerInScope = false;
        Version = "";
        encodeObsoleteFormatV1 = Encode.UTF_8;
        ExcludeMimeTypes = new ArrayList<>();
        rlist = new ArrayList<AppParmsIni>();
        aparms = null;
        apv = null;
        ReqResList = new ArrayList<PRequestResponse>();
        currentrequest = 0;
        row = 0;
        JSONSyntaxErrors = new ArrayList<>();
        ExceptionErrors = new ArrayList<>();
        tabIndex = -1;
        initGsonReqRes();
        initAppParmAndSequcenceList();
    }

    public String getVersion() {
        return Version;
    }

    public Encode getEncodeFormatV1() {
        return encodeObsoleteFormatV1;
    }

    private boolean hasErrors() {
        if (JSONSyntaxErrors.size() > 0 || ExceptionErrors.size() > 0) {
            return true;
        }
        return false;
    }

    /**
     * initialize gsonObjectPrequestResponse for v1
     *
     * @deprecated this function is obsolete because new JSON format will be used GSONSaveObjectV2
     */
    @Deprecated
    private void initGsonReqRes() {
        if (gsonObjectPRequestResponse == null) {
            gsonObjectPRequestResponse = new GSONSaveObject.GsonPRequestResponse();
        } else {
            gsonObjectPRequestResponse.init();
        }
    }

    /**
     * initialize gsonPRequestResponse
     *
     * <p>alternative new method after obsoleted initGsonReqRes
     */
    private void initGsonReqResV2() {
        if (gsonPRequestResponse == null) {
            gsonPRequestResponse = new GSONSaveObjectV2.GsonPRequestResponse();
        } else {
            gsonPRequestResponse.init();
        }
    }

    private void initAppParmAndSequcenceList() {
        if (appParmAndSequenceList == null) {
            appParmAndSequenceList = new ArrayList<>();
        } else {
            appParmAndSequenceList.clear();
        }
    }

    public List<AppParmAndSequence> getAppParmAndSequenceList() {
        return appParmAndSequenceList;
    }

    public ArrayList<AppParmsIni> Getrlist() {
        return rlist;
    }

    public ArrayList<PRequestResponse> GetMacroRequests() {
        return ReqResList;
    }

    public int getCurrentRequest() {
        return currentrequest;
    }

    private String GetString(GsonParser.EventType ev, Object value, String defval) {
        String v = defval;
        if (value instanceof String) {
            v = (String) value;
        }
        return v;
    }

    private int GetNumber(GsonParser.EventType ev, Object value, int defval) {
        int i = defval;
        if (value instanceof Number) {
            Number n = (Number) value;
            i = n.intValue();
        }

        return i;
    }

    private boolean Getboolean(GsonParser.EventType ev, Object value, boolean defval) {
        boolean b = defval;
        if (value instanceof Boolean) {
            Boolean bobj = (Boolean) value;
            b = bobj;
        }
        return b;
    }

    boolean GParse(
            ParmGenStack<String> astack, GsonParser.EventType ev, String name, Object value) {
        String current = astack.getCurrent();
        switch (astack.size()) {
            case 0:
                switch (ev) {
                    case START_OBJECT:
                        break;
                    case END_OBJECT:
                        break;
                    case START_ARRAY:
                        break;
                    case END_ARRAY:
                        break;
                    default:
                        if (name.equalsIgnoreCase("LANG")) {
                            encodeObsoleteFormatV1 = Encode.getEnum(GetString(ev, value, "UTF-8"));
                        } else if (name.equalsIgnoreCase("PROXYINSCOPE")) {
                            ProxyInScope = Getboolean(ev, value, false);
                        } else if (name.equalsIgnoreCase("INTRUDERINSCOPE")) {
                            IntruderInScope = Getboolean(ev, value, true);
                        } else if (name.equalsIgnoreCase("REPEATERINSCOPE")) {
                            RepeaterInScope = Getboolean(ev, value, true);
                        } else if (name.equalsIgnoreCase("SCANNERINSCOPE")) {
                            ScannerInScope = Getboolean(ev, value, true);
                        } else if (name.equalsIgnoreCase("CURRENTREQUEST")) {
                            currentrequest = GetNumber(ev, value, 0);
                        } else if (name.equalsIgnoreCase("VERSION")) {
                            Version = GetString(ev, value, "");
                        }
                        break;
                }
                break;
            case 1:
                switch (ev) {
                    case START_OBJECT:
                        if (current != null) {
                            if (current.equalsIgnoreCase("APPPARMSINI_LIST")) { // V1
                                // ParmVars.plog.debuglog(0, "START_OBJECT level1 name:" + current);
                                aparms = new AppParmsIni(); // add new record
                                // aparms.parmlist = new ArrayList<AppValue>();
                            } else if ((current.equalsIgnoreCase("PREQUESTRESPONSE")
                                    || current.equalsIgnoreCase("PREQUESTRESPONSES"))) { // V1
                                initGsonReqRes();
                            } else if (current.equalsIgnoreCase("APPPARMANDSEQUENCES")) { // V2
                                appParmAndSequence = new AppParmAndSequence();
                                logger4j.debug("astack:1 START_OBJECT " + current.toUpperCase());
                            }
                        }
                        break;
                    case END_OBJECT:
                        if (!hasErrors() && current != null) {
                            if (current.equalsIgnoreCase("APPPARMSINI_LIST")) { // V1
                                if (aparms != null && rlist != null) {
                                    if (aparms.getTypeVal() == AppParmsIni.T_CSV) {
                                        String decodedname = "";
                                        try {
                                            decodedname =
                                                    URLdecodeFromJSONThrows(aparms.getCsvName());
                                            aparms.crtFrl(decodedname, true);
                                        } catch (Exception e) {
                                            logger4j.error(
                                                    "decode failed:[" + aparms.getCsvName() + "]",
                                                    e);
                                            ExceptionErrors.add(e);
                                        }
                                    }

                                    // aparms.setRow(row);row++;
                                    // aparms.crtGenFormat(true);
                                    rlist.add(aparms);
                                }
                                aparms = null;
                            } else if (gsonObjectPRequestResponse != null
                                    && (current.equalsIgnoreCase("PREQUESTRESPONSE")
                                            || current.equalsIgnoreCase(
                                                    "PREQUESTRESPONSES"))) { // V1
                                if (gsonObjectPRequestResponse.PRequest64 != null) {
                                    byte[] binreq =
                                            Base64.getDecoder()
                                                    .decode(
                                                            gsonObjectPRequestResponse
                                                                    .PRequest64); // same as
                                    // decode(src.getBytes(StandardCharsets.ISO_8859_1))
                                    byte[] binres =
                                            Base64.getDecoder()
                                                    .decode(gsonObjectPRequestResponse.PResponse64);

                                    PRequestResponse pqr =
                                            new PRequestResponse(
                                                    gsonObjectPRequestResponse.Host,
                                                    gsonObjectPRequestResponse.Port,
                                                    gsonObjectPRequestResponse.SSL,
                                                    binreq,
                                                    binres,
                                                    encodeObsoleteFormatV1,
                                                    encodeObsoleteFormatV1);
                                    if (gsonObjectPRequestResponse.Disabled) {
                                        pqr.Disable();
                                    }
                                    pqr.setComments(gsonObjectPRequestResponse.Comments);
                                    pqr.setError(gsonObjectPRequestResponse.Error);
                                    ReqResList.add(pqr);
                                    initGsonReqRes();
                                }
                            } else if (current.equalsIgnoreCase("APPPARMANDSEQUENCES")) { // V2
                                if (appParmAndSequenceList != null && appParmAndSequence != null) {
                                    appParmAndSequenceList.add(appParmAndSequence);
                                }
                                appParmAndSequence = null;
                                logger4j.debug("astack:1 END_OBJECT " + current.toUpperCase());
                            }
                        }
                        break;
                    case START_ARRAY:
                    case END_ARRAY:
                        break;
                    default:
                        if (aparms != null) { // V1
                            if (name.equalsIgnoreCase("URL")) {
                                aparms.setUrl(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("LEN")) {
                                aparms.setLen(GetNumber(ev, value, 0));
                            } else if (name.equalsIgnoreCase("TYPEVAL")) {
                                aparms.setTypeVal(GetNumber(ev, value, 0));
                            } else if (name.equalsIgnoreCase("INIVAL")) {
                                aparms.setIniVal(GetNumber(ev, value, 0));
                            } else if (name.equalsIgnoreCase("MAXVAL")) {
                                aparms.setMaxVal(GetNumber(ev, value, 0));
                            } else if (name.equalsIgnoreCase("CSVNAME")) {
                                aparms.setCsvName(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("PAUSE")) {
                                aparms.initPause(Getboolean(ev, value, false));
                            } else if (name.equalsIgnoreCase("TRACKFROMSTEP")) {
                                aparms.setTrackFromStep(GetNumber(ev, value, 0));
                            } else if (name.equalsIgnoreCase("SETTOSTEP")) {
                                int stepno = GetNumber(ev, value, ParmVars.TOSTEPANY);
                                if (Version.isEmpty()) {
                                    if (stepno <= 0) {
                                        stepno = ParmVars.TOSTEPANY;
                                    }
                                }
                                aparms.setSetToStep(stepno);
                            } else if (name.equalsIgnoreCase("RELATIVECNTFILENAME")) {
                                aparms.setRelativeCntFileName(GetString(ev, value, ""));
                            }
                        } else if (current != null) {
                            if (current.equalsIgnoreCase("PREQUESTRESPONSE")
                                    || current.equalsIgnoreCase("PREQUESTRESPONSES")) { // V1
                                if (gsonObjectPRequestResponse != null) {
                                    if (name.equalsIgnoreCase("PREQUEST")
                                            || name.equalsIgnoreCase("PREQUEST64")) {
                                        gsonObjectPRequestResponse.PRequest64 =
                                                GetString(ev, value, "");
                                    } else if (name.equalsIgnoreCase("PRESPONSE")
                                            || name.equalsIgnoreCase("PRESPONSE64")) {
                                        gsonObjectPRequestResponse.PResponse64 =
                                                GetString(ev, value, "");
                                    } else if (name.equalsIgnoreCase("HOST")) {
                                        gsonObjectPRequestResponse.Host = GetString(ev, value, "");
                                    } else if (name.equalsIgnoreCase("PORT")) {
                                        gsonObjectPRequestResponse.Port = GetNumber(ev, value, 0);
                                    } else if (name.equalsIgnoreCase("SSL")) {
                                        gsonObjectPRequestResponse.SSL =
                                                Getboolean(ev, value, false);
                                    } else if (name.equalsIgnoreCase("COMMENTS")) {
                                        gsonObjectPRequestResponse.Comments =
                                                GetString(ev, value, "");
                                    } else if (name.equalsIgnoreCase("DISABLED")) {
                                        gsonObjectPRequestResponse.Disabled =
                                                Getboolean(ev, value, false);
                                    } else if (name.equalsIgnoreCase("ERROR")) {
                                        gsonObjectPRequestResponse.Error =
                                                Getboolean(ev, value, false);
                                    }
                                }
                            } else if (current.equalsIgnoreCase("EXCLUDEMIMETYPES")) {
                                if (!Version.isEmpty()) {
                                    String exmime = GetString(ev, value, "");
                                    if (exmime != null && exmime.length() > 0) {
                                        addExcludeMimeType(exmime);
                                    }
                                }
                            } else if (current.equalsIgnoreCase("APPPARMANDSEQUENCES")) { // V2
                                if (appParmAndSequence != null) {
                                    if (name.equalsIgnoreCase("MYPAGEINDEX")) {
                                        appParmAndSequence.myPageIndex = GetNumber(ev, value, -1);
                                    } else if (name.equalsIgnoreCase("CURRENTREQUEST")) {
                                        appParmAndSequence.currentRequest =
                                                GetNumber(ev, value, -1);
                                    } else if (name.equalsIgnoreCase("SEQUENCECHARSETNAME")) {
                                        appParmAndSequence.sequenceEncode =
                                                Encode.getEnum(GetString(ev, value, "UTF-8"));
                                    }
                                }
                            }
                        }
                        break;
                }
                break;
            case 2:
                switch (ev) {
                    case START_OBJECT:
                        if (current != null) {
                            if (current.equalsIgnoreCase("APPPARMSINI_LISTS")) { // V2
                                // ParmVars.plog.debuglog(0, "START_OBJECT level1 name:" + current);
                                aparms = new AppParmsIni(); // add new record
                                // aparms.parmlist = new ArrayList<AppValue>();
                            } else if (current.equalsIgnoreCase("APPVALUE_LIST")) { // v1
                                // ParmVars.plog.debuglog(0, "START_OBJECT level2 name:" + current);
                                apv = new AppValue();
                            } else if (current.equalsIgnoreCase("PREQUESTRESPONSES")) { // v2
                                initGsonReqResV2();
                            }
                        }
                        break;
                    case END_OBJECT:
                        if (!hasErrors() && current != null) {
                            if (current.equalsIgnoreCase("APPVALUE_LIST")) { // v1
                                if (apv != null && aparms != null) {
                                    aparms.addAppValue(apv);
                                }
                            } else if (current.equalsIgnoreCase("APPPARMSINI_LISTS")) { // V2
                                if (appParmAndSequence != null && aparms != null) {
                                    if (aparms.getTypeVal() == AppParmsIni.T_CSV) {
                                        String decodedname = "";
                                        try {
                                            decodedname =
                                                    URLdecodeFromJSONThrows(aparms.getCsvName());
                                            aparms.crtFrl(decodedname, true);
                                        } catch (Exception e) {
                                            logger4j.error(
                                                    "decode failed:[" + aparms.getCsvName() + "]",
                                                    e);
                                            ExceptionErrors.add(e);
                                        }
                                    }
                                    appParmAndSequence.appParmsIniList.add(aparms);
                                }
                                aparms = null;
                            } else if (current.equalsIgnoreCase("PREQUESTRESPONSES")) { // v2
                                if (appParmAndSequence != null
                                        && gsonPRequestResponse != null
                                        && gsonPRequestResponse.PRequest64 != null) {
                                    byte[] binreq =
                                            Base64.getDecoder()
                                                    .decode(
                                                            gsonPRequestResponse
                                                                    .PRequest64); // same as
                                    // decode(src.getBytes(StandardCharsets.ISO_8859_1))
                                    byte[] binres =
                                            Base64.getDecoder()
                                                    .decode(gsonPRequestResponse.PResponse64);

                                    Encode requestEncode = appParmAndSequence.sequenceEncode;
                                    Encode responseEncode = appParmAndSequence.sequenceEncode;

                                    if (gsonPRequestResponse.RequestCharsetName != null
                                            && !gsonPRequestResponse.RequestCharsetName.isEmpty()) {
                                        requestEncode =
                                                Encode.getEnum(
                                                        gsonPRequestResponse.RequestCharsetName);
                                    }

                                    if (gsonPRequestResponse.ResponseCharsetName != null
                                            && !gsonPRequestResponse.ResponseCharsetName
                                                    .isEmpty()) {
                                        responseEncode =
                                                Encode.getEnum(
                                                        gsonPRequestResponse.ResponseCharsetName);
                                    }

                                    if (requestEncode == null) {
                                        requestEncode = Encode.ISO_8859_1;
                                    }

                                    if (responseEncode == null) {
                                        responseEncode = Encode.ISO_8859_1;
                                    }

                                    PRequestResponse pqr =
                                            new PRequestResponse(
                                                    gsonPRequestResponse.Host,
                                                    gsonPRequestResponse.Port,
                                                    gsonPRequestResponse.SSL,
                                                    binreq,
                                                    binres,
                                                    requestEncode,
                                                    responseEncode);
                                    if (gsonPRequestResponse.Disabled) {
                                        pqr.Disable();
                                    }
                                    pqr.setComments(gsonPRequestResponse.Comments);
                                    pqr.setError(gsonPRequestResponse.Error);
                                    appParmAndSequence.pRequestResponses.add(pqr);
                                    initGsonReqResV2();
                                }
                            }
                        }
                        apv = null;
                        break;
                    case START_ARRAY:
                    case END_ARRAY:
                        break;
                    default:
                        if (apv != null) { // v1
                            if (name.equalsIgnoreCase("VALPART")) {
                                if (!apv.setValPart(GetString(ev, value, ""))) {
                                    JSONSyntaxErrors.add("VALPART has no value:[" + value + "]");
                                }
                            } else if (name.equalsIgnoreCase("ISMODIFY")) {
                                if (Getboolean(ev, value, true) == false) {
                                    apv.setEnabled(false);
                                }
                            } else if (name.equalsIgnoreCase("ISENABLED")) {
                                if (Getboolean(ev, value, true) == false) {
                                    apv.setEnabled(false);
                                }
                            } else if (name.equalsIgnoreCase("ISNOCOUNT")) {
                                if (Getboolean(ev, value, true) == true) {
                                    apv.setNoCount();
                                } else {
                                    apv.clearNoCount();
                                }
                            } else if (name.equalsIgnoreCase("CSVPOS")) {
                                apv.setCsvpos(GetNumber(ev, value, 0));
                            } else if (name.equalsIgnoreCase("VALUE")) {
                                if (!apv.setURLencodedVal(GetString(ev, value, ""))) {
                                    JSONSyntaxErrors.add("Invalid VALUE :[" + value + "]");
                                }
                            } else if (name.equalsIgnoreCase("RESURL")) {
                                apv.setresURL(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("RESREGEX")) {
                                apv.setresRegexURLencoded(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("RESVALPART")) {
                                apv.setresPartType(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("RESREGEXPOS")) {
                                apv.setResRegexPos(GetNumber(ev, value, 0));
                            } else if (name.equalsIgnoreCase("TOKEN")) {
                                apv.setToken(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("URLENCODE")) {
                                apv.setUrlEncode(Getboolean(ev, value, false));
                            } else if (name.equalsIgnoreCase("FROMSTEPNO")) {
                                apv.setFromStepNo(GetNumber(ev, value, -1));
                            } else if (name.equalsIgnoreCase("TOSTEPNO")) {
                                int stepno = GetNumber(ev, value, ParmVars.TOSTEPANY);
                                if (Version.isEmpty()) {
                                    if (stepno <= 0) {
                                        stepno = ParmVars.TOSTEPANY;
                                    }
                                }
                                apv.setToStepNo(stepno);
                            } else if (name.equalsIgnoreCase("TOKENTYPE")) {
                                apv.setTokenTypeName(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("RESENCODETYPE")) {
                                apv.setResEncodeTypeFromString(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("CONDTARGETNO")) {
                                apv.setCondTargetNo(GetNumber(ev, value, 0));
                            } else if (name.equalsIgnoreCase("CONDREGEX")) {
                                apv.setCondRegexURLencoded(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("CONDREGEXTARGETISREQUEST")) {
                                apv.setRequestIsCondTegexTarget(Getboolean(ev, value, false));
                            } else if (name.equalsIgnoreCase("REPLACEZEROSIZE")) {
                                apv.setReplaceZeroSize(Getboolean(ev, value, false));
                            }
                        } else if (current != null) {
                            if (current.equalsIgnoreCase("PREQUESTRESPONSES")) { // v2
                                if (gsonPRequestResponse != null) {
                                    if (name.equalsIgnoreCase("PREQUEST")
                                            || name.equalsIgnoreCase("PREQUEST64")) {
                                        gsonPRequestResponse.PRequest64 = GetString(ev, value, "");
                                    } else if (name.equalsIgnoreCase("PRESPONSE")
                                            || name.equalsIgnoreCase("PRESPONSE64")) {
                                        gsonPRequestResponse.PResponse64 = GetString(ev, value, "");
                                    } else if (name.equalsIgnoreCase("HOST")) {
                                        gsonPRequestResponse.Host = GetString(ev, value, "");
                                    } else if (name.equalsIgnoreCase("PORT")) {
                                        gsonPRequestResponse.Port = GetNumber(ev, value, 0);
                                    } else if (name.equalsIgnoreCase("SSL")) {
                                        gsonPRequestResponse.SSL = Getboolean(ev, value, false);
                                    } else if (name.equalsIgnoreCase("COMMENTS")) {
                                        gsonPRequestResponse.Comments = GetString(ev, value, "");
                                    } else if (name.equalsIgnoreCase("DISABLED")) {
                                        gsonPRequestResponse.Disabled =
                                                Getboolean(ev, value, false);
                                    } else if (name.equalsIgnoreCase("ERROR")) {
                                        gsonPRequestResponse.Error = Getboolean(ev, value, false);
                                    } else if (name.equalsIgnoreCase("REQUESTCHARSETNAME")) {
                                        gsonPRequestResponse.RequestCharsetName =
                                                GetString(ev, value, "UTF-8");
                                    } else if (name.equalsIgnoreCase("RESPONSECHARSETNAME")) {
                                        gsonPRequestResponse.ResponseCharsetName =
                                                GetString(ev, value, "UTF-8");
                                    }
                                }
                            } else if (current.equalsIgnoreCase("APPPARMSINI_LISTS")) { // v2
                                if (aparms != null) {
                                    if (name.equalsIgnoreCase("URL")) {
                                        aparms.setUrl(GetString(ev, value, ""));
                                    } else if (name.equalsIgnoreCase("LEN")) {
                                        aparms.setLen(GetNumber(ev, value, 0));
                                    } else if (name.equalsIgnoreCase("TYPEVAL")) {
                                        aparms.setTypeVal(GetNumber(ev, value, 0));
                                    } else if (name.equalsIgnoreCase("INIVAL")) {
                                        aparms.setIniVal(GetNumber(ev, value, 0));
                                    } else if (name.equalsIgnoreCase("MAXVAL")) {
                                        aparms.setMaxVal(GetNumber(ev, value, 0));
                                    } else if (name.equalsIgnoreCase("CSVNAME")) {
                                        aparms.setCsvName(GetString(ev, value, ""));
                                    } else if (name.equalsIgnoreCase("PAUSE")) {
                                        aparms.initPause(Getboolean(ev, value, false));
                                    } else if (name.equalsIgnoreCase("TRACKFROMSTEP")) {
                                        aparms.setTrackFromStep(GetNumber(ev, value, 0));
                                    } else if (name.equalsIgnoreCase("SETTOSTEP")) {
                                        int stepno = GetNumber(ev, value, ParmVars.TOSTEPANY);
                                        if (Version.isEmpty()) {
                                            if (stepno <= 0) {
                                                stepno = ParmVars.TOSTEPANY;
                                            }
                                        }
                                        aparms.setSetToStep(stepno);
                                    } else if (name.equalsIgnoreCase("RELATIVECNTFILENAME")) {
                                        aparms.setRelativeCntFileName(GetString(ev, value, ""));
                                    }
                                }
                            }
                        }
                        break;
                }
                break;
            case 3:
                switch (ev) {
                    case START_OBJECT:
                        if (current.equalsIgnoreCase("APPVALUE_LISTS")) { // v2
                            // ParmVars.plog.debuglog(0, "START_OBJECT level2 name:" + current);
                            apv = new AppValue();
                        }
                        break;
                    case END_OBJECT:
                        if (!hasErrors() && current != null) {
                            if (current.equalsIgnoreCase("APPVALUE_LISTS")) { // v2
                                if (apv != null && aparms != null) {
                                    aparms.addAppValue(apv);
                                }
                            }
                        }
                        break;
                    default:
                        if (apv != null) { // v2
                            if (name.equalsIgnoreCase("VALPART")) {
                                if (!apv.setValPart(GetString(ev, value, ""))) {
                                    JSONSyntaxErrors.add("VALPART has no value:[" + value + "]");
                                }
                            } else if (name.equalsIgnoreCase("ISMODIFY")) {
                                if (Getboolean(ev, value, true) == false) {
                                    apv.setEnabled(false);
                                }
                            } else if (name.equalsIgnoreCase("ISENABLED")) {
                                if (Getboolean(ev, value, true) == false) {
                                    apv.setEnabled(false);
                                }
                            } else if (name.equalsIgnoreCase("ISNOCOUNT")) {
                                if (Getboolean(ev, value, true) == true) {
                                    apv.setNoCount();
                                } else {
                                    apv.clearNoCount();
                                }
                            } else if (name.equalsIgnoreCase("CSVPOS")) {
                                apv.setCsvpos(GetNumber(ev, value, 0));
                            } else if (name.equalsIgnoreCase("VALUE")) {
                                if (!apv.setURLencodedVal(GetString(ev, value, ""))) {
                                    JSONSyntaxErrors.add("Invalid VALUE :[" + value + "]");
                                }
                            } else if (name.equalsIgnoreCase("RESURL")) {
                                apv.setresURL(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("RESREGEX")) {
                                apv.setresRegexURLencoded(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("RESVALPART")) {
                                apv.setresPartType(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("RESREGEXPOS")) {
                                apv.setResRegexPos(GetNumber(ev, value, 0));
                            } else if (name.equalsIgnoreCase("TOKEN")) {
                                apv.setToken(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("URLENCODE")) {
                                apv.setUrlEncode(Getboolean(ev, value, false));
                            } else if (name.equalsIgnoreCase("FROMSTEPNO")) {
                                apv.setFromStepNo(GetNumber(ev, value, -1));
                            } else if (name.equalsIgnoreCase("TOSTEPNO")) {
                                int stepno = GetNumber(ev, value, ParmVars.TOSTEPANY);
                                if (Version.isEmpty()) {
                                    if (stepno <= 0) {
                                        stepno = ParmVars.TOSTEPANY;
                                    }
                                }
                                apv.setToStepNo(stepno);
                            } else if (name.equalsIgnoreCase("TOKENTYPE")) {
                                apv.setTokenTypeName(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("RESENCODETYPE")) {
                                apv.setResEncodeTypeFromString(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("CONDTARGETNO")) {
                                apv.setCondTargetNo(GetNumber(ev, value, 0));
                            } else if (name.equalsIgnoreCase("CONDREGEX")) {
                                apv.setCondRegexURLencoded(GetString(ev, value, ""));
                            } else if (name.equalsIgnoreCase("CONDREGEXTARGETISREQUEST")) {
                                apv.setRequestIsCondTegexTarget(Getboolean(ev, value, false));
                            } else if (name.equalsIgnoreCase("REPLACEZEROSIZE")) {
                                apv.setReplaceZeroSize(Getboolean(ev, value, false));
                            }
                        }
                        break;
                }
                break;
            default:
                break;
        }

        return !hasErrors();
    }

    public void addExcludeMimeType(String exttype) {
        ExcludeMimeTypes.add(exttype);
    }

    public List<String> getExcludeMimeTypes() {
        return ExcludeMimeTypes;
    }

    private String getindent(int idt, String keyname) {
        String idtstr = "";
        for (int i = 0; i < idt; i++) {
            idtstr += "  ";
        }
        return idtstr + (keyname == null ? "" : (keyname + ":"));
    }

    /**
     * JSON parser listener for GSON
     *
     * @param git
     * @param etype
     * @param keyname
     * @param value
     * @param level
     */
    @Override
    public boolean receiver(
            GsonIterator git, GsonParser.EventType etype, String keyname, Object value, int level) {
        boolean noerror = true;
        switch (etype) {
            case START_OBJECT:
                logger4j.debug(
                        getindent(level - 1, keyname) + "{" + level + " astack:" + astack.size());
                break;
            case END_OBJECT:
                logger4j.debug(
                        getindent(level - 1, keyname) + level + "}" + " astack:" + astack.size());
                break;
            case START_ARRAY:
                astack.push(keyname); // array title name
                logger4j.debug(
                        getindent(level - 1, keyname) + "[" + level + " astack:" + astack.size());
                break;
            case END_ARRAY:
                String ep = astack.pop();
                logger4j.debug(
                        getindent(level - 1, keyname)
                                + level
                                + "]"
                                + " astack:"
                                + astack.size()); // keyname == ep
                break;
            case BOOLEAN:
                if (value instanceof Boolean) {
                    Boolean bobj = (Boolean) value;
                    boolean b = bobj.booleanValue();
                    logger4j.debug(
                            getindent(level, keyname)
                                    + (b ? "TRUE" : "FALSE")
                                    + " astack:"
                                    + astack.size());
                }
                break;
            case NUMBER:
                if (value instanceof Number) {
                    Number n = (Number) value;
                    logger4j.debug(getindent(level, keyname) + n);
                }
                break;
            case STRING:
                if (value instanceof String) {
                    String s = (String) value;
                    String enckeyname = git.getKeyName();
                    logger4j.debug(
                            getindent(level, keyname)
                                    + (enckeyname != null ? enckeyname + "->" : "")
                                    + "\""
                                    + s
                                    + "\""
                                    + " astack:"
                                    + astack.size());
                }
                break;
            case NULL:
                logger4j.debug(getindent(level, keyname) + "NULL" + " astack:" + astack.size());
                break;
            default:
                break;
        }

        return GParse(astack, etype, keyname, value);
    }

    /**
     * decode URLencoded JSON(UTF-8) String. if failed decode then throws Exception.
     *
     * @param urlencoded
     * @return
     * @throws UnsupportedEncodingException
     */
    private String URLdecodeFromJSONThrows(String urlencoded) throws UnsupportedEncodingException {
        String decodedvalue = null;
        decodedvalue = URLDecoder.decode(urlencoded, JSONFileIANACharsetName);
        return decodedvalue;
    }
}
