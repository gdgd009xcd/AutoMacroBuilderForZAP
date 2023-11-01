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

import static org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables.JSONFileIANACharsetName;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ResourceBundle;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** @author gdgd009xcd */
//
// class AppValue
//
public class AppValue {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    // valparttype,         value, token, tamattack,tamadvance,tamposition,urlencode
    // 置換位置,置換しない,  value, Name,  Attack,   Advance,   Position,   URLencode
    private String valpart; // 置換位置
    private int valparttype; //  1-query, 2-body  3-header  4-path.... 16(10000) bit == no count
    // 32(100000) == no modify
    private String value = null; // Target Regex String to embed value in
    private Pattern valueregex; //  Target Regex to embed value in

    private int csvpos;

    private UUID trackkey = null;
    private String resURL = "";
    private Pattern Pattern_resURL = null;
    private String resRegex = "";
    private Pattern Pattern_resRegex = null;
    private int resPartType;
    private int resRegexPos = -1; // Tracking token　position on page(start 0)
    private String token; // Tracking token name
    //
    // 下記パラメータは、GUI操作時の一時保存値で、保存対象外。スキャン時は未使用。
    // This parameter does not use when scanning. only  temporarily use  for GUI manipulation
    private String resFetchedValue =
            null; // レスポンスからフェッチしたtokenの値 Token obtained from response during tracking process

    private TokenTypeNames tokentype = TokenTypeNames.INPUT;

    // conditional parameter tracking feature
    private int condTargetNo = -1; // conditinal tracking targetNo default: -1(any == wildcard "*")
    private String condRegex = ""; // conditional tracking regex. if requestNO == condTargetNo
    private Pattern Pattern_condRegex = null; // compiled pattern of condRegex
    // and it's request or response matched this regex then cache value  is updated.
    private boolean condRegexTargetIsRequest =
            false; // if this value is true then condRegex matches request.

    private boolean replaceZeroSize =
            false; // if this value is true, request parameter replaced even if fetched tracking
    // value is zero size string.

    public enum TokenTypeNames {
        DEFAULT,
        INPUT,
        LOCATION,
        HREF,
        XCSRF,
        TEXT,
        TEXTAREA,
        JSON,
        ACTION,
    };

    private boolean urlencode; // Whether to  encode URL

    private ResEncodeTypes resencodetype =
            ResEncodeTypes.RAW; // 追跡元のエンコードタイプ Encode type of tracking param json/raw/urlencode

    public enum ResEncodeTypes {
        RAW,
        JSON,
        URLENCODE,
    }

    private int fromStepNo = -1; // TRACK追跡元 <0 :　無条件で追跡　>=0: 指定StepNoのリクエスト追跡
    // Line number of response from which  getting tracking parameter  in RequestList sequence
    // < 0: get tracking value from any response
    // >=0: get tracking value from specified request line number's response
    private int toStepNo = EnvironmentVariables.TOSTEPANY; // TRACK:更新先
    // 　>0:指定したStepNoのリクエスト更新
    // Line number of request to which setting tracking paramter  in RequestList sequence
    //  <0 : No Operation.
    //  >=0 and < TOSTEPANY: set tracking value to specified line number's request
    //  ==TOSTEPANY: set tracking value to any request.

    public static final int V_QUERY = 1;
    public static final int V_BODY = 2;
    public static final int V_HEADER = 3;
    public static final int V_PATH = 4;
    public static final int V_AUTOTRACKBODY = 5; //  response body tracking
    public static final int V_REQTRACKBODY = 6; // password(request body) tracking
    public static final int V_REQTRACKQUERY = 7; // password(request query) tracking
    public static final int V_REQTRACKPATH = 8; // password (request path) tracking
    public static final int C_NOCOUNT = 16;
    public static final int C_VTYPE = 15;
    public static String[] ctypestr = {
        // V_QUERY ==1
        "",
        "query",
        "body",
        "header",
        "path",
        "responsebody",
        "requestbody",
        "requestquery",
        "requestpath",
        null,
        null,
        null,
        null,
        null,
        null,
        null // 0-15
    };

    public static final int I_APPEND = 0;
    public static final int I_INSERT = 1;
    public static final int I_REPLACE = 2;
    public static final int I_REGEX = 3;

    private static String[] payloadpositionnames = {
        // 診断パターン挿入位置
        // append 値末尾に追加
        // insert 値先頭に挿入
        // replace 値をパターンに置き換え
        // regex   埋め込み箇所正規表現指定
        "append", "insert", "replace", "regex", null
    };

    private boolean enabled = true; // enable/disable flag

    private void initctype() {
        Pattern_condRegex = null;
        condTargetNo = -1;
        condRegex = null;
        trackkey = null;
        resFetchedValue = null;
        enabled = true;
        tokentype = TokenTypeNames.INPUT;
        replaceZeroSize = false;
    }

    public AppValue() {
        setVal(null);
        initctype();
        resRegexPos = -1;
    }

    public AppValue(String _Type, boolean _disabled, String _value) {
        initctype();
        setValPart(_Type);
        setEnabled(!_disabled); // NOT
        // value = _value;
        setVal(_value);
        resRegexPos = -1;
    }

    public AppValue(
            String _Type, boolean _disabled, int _csvpos, String _value, boolean increment) {
        initctype();
        setValPart(_Type);
        setEnabled(!_disabled); // NOT
        csvpos = _csvpos;
        // value = _value;
        setVal(_value);
        resRegexPos = -1;
        if (increment) {
            clearNoCount();
        } else {
            setNoCount();
        }
    }

    public AppValue(String _Type, boolean _disabled, String _value, boolean increment) {
        initctype();
        setValPart(_Type);
        setEnabled(!_disabled); // NOT
        // value = _value;
        setVal(_value);
        resRegexPos = -1;
        if (increment) {
            clearNoCount();
        } else {
            setNoCount();
        }
    }

    public AppValue(
            String _Type,
            boolean _disabled,
            String _value,
            String _resURL,
            String _resRegex,
            String _resPartType,
            String _resRegexPos,
            String _token,
            boolean _urlenc,
            int _fromStepNo,
            int _toStepNo,
            String _tokentypename,
            String condRegex,
            int condTargetNo,
            boolean condRegexTargetIsRequest,
            boolean replaceZeroSize) {
        initctype();
        setValPart(_Type);
        setEnabled(!_disabled); // NOT
        // value = _value;
        setVal(_value);
        setresURL(_resURL);
        setresRegex(_resRegex);
        setresPartType(_resPartType);
        setResRegexPosFromString(_resRegexPos);
        token = _token;
        urlencode = _urlenc;
        fromStepNo = _fromStepNo;
        toStepNo = _toStepNo;
        tokentype = parseTokenTypeName(_tokentypename);
        setCondRegex(condRegex);
        this.condTargetNo = condTargetNo;
        this.condRegexTargetIsRequest = condRegexTargetIsRequest;
        this.replaceZeroSize = replaceZeroSize;
    }

    /**
     * Get toStepNo: Line number of request to which setting tracking value in RequestList sequence.
     *
     * @return
     */
    public int getToStepNo() {
        return this.toStepNo;
    }

    /**
     * Set toStepNo: line number of request to which setting tracking value in RequestList sequence.
     *
     * @param toStepNo
     */
    public void setToStepNo(int toStepNo) {
        this.toStepNo = toStepNo;
    }

    /**
     * Get fromStepNo: Line number of response from which getting tracking parameter in RequestList
     * sequence
     *
     * @return
     */
    public int getFromStepNo() {
        return this.fromStepNo;
    }

    /**
     * Set fromStepNo: Line number of response from which getting tracking parameter in RequestList
     * sequence
     *
     * @param fromStepNo
     */
    public void setFromStepNo(int fromStepNo) {
        this.fromStepNo = fromStepNo;
    }

    /**
     * Whether to encode URL
     *
     * @return
     */
    public boolean isUrlEncode() {
        return this.urlencode;
    }

    /**
     * Set urlencode value
     *
     * @param urlencode
     */
    public void setUrlEncode(boolean urlencode) {
        this.urlencode = urlencode;
    }

    /** Get TokenType value */
    public TokenTypeNames getTokenType() {
        return this.tokentype;
    }

    /**
     * Set TokenType value
     *
     * @param tokentype
     */
    public void setTokenType(TokenTypeNames tokentype) {
        this.tokentype = tokentype;
    }

    /**
     * Get resFetchedValue This parameter does not use when scanning. only temporarily use for GUI
     * manipulation
     *
     * @param resFetchedValue
     */
    public void setResFetchedValue(String resFetchedValue) {
        this.resFetchedValue = resFetchedValue;
    }

    public String getResFetchedValue() {
        return this.resFetchedValue;
    }

    /**
     * Set token value
     *
     * @param token
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Get token value
     *
     * @return
     */
    public String getToken() {
        return this.token;
    }

    /**
     * Get csvpos value
     *
     * @return
     */
    public int getCsvpos() {
        return this.csvpos;
    }

    /**
     * Set csvpos value
     *
     * @param csvpos
     */
    public void setCsvpos(int csvpos) {
        this.csvpos = csvpos;
    }

    /**
     * Get the key. If the key has a null value, the key is created
     *
     * @return UUID
     */
    public synchronized UUID getTrackKey() {
        if (trackkey == null) {
            trackkey = UUIDGenerator.getUUID();
        }
        return trackkey;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean b) {
        enabled = b;
    }

    public String getPayloadPositionName(int it) {
        if (payloadpositionnames.length > it && it >= 0) {
            return payloadpositionnames[it];
        }
        return "";
    }

    /**
     * Get ResEncodeTypes : response page content type JSON/RAW/URLENCODE..
     *
     * @return
     */
    public ResEncodeTypes getResEncodeType() {
        return this.resencodetype;
    }

    /**
     * Convert string representation to ResEncodeType and set its value to resencodetype parameter
     *
     * @param t
     */
    public void setResEncodeTypeFromString(String t) {
        resencodetype = parseResEncodeTypeString(t);
    }

    /**
     * Convert string represantation to ResEncodeTypes
     *
     * @param t
     * @return
     */
    public ResEncodeTypes parseResEncodeTypeString(String t) {
        ResEncodeTypes[] encarray = ResEncodeTypes.values();
        if (t != null && !t.isEmpty()) {
            String tupper = t.toUpperCase();
            for (ResEncodeTypes enc : encarray) {
                if (enc.name().toUpperCase().equals(tupper)) {
                    return enc;
                }
            }
        }
        return ResEncodeTypes.RAW;
    }

    public static String[] makePayloadPositionNames() {
        return new String[] {
            payloadpositionnames[I_APPEND],
            payloadpositionnames[I_INSERT],
            payloadpositionnames[I_REPLACE],
            payloadpositionnames[I_REGEX]
        };
    }

    // ParmGenNew 数値、追跡テーブル用　ターゲットリクエストパラメータタイプリスト
    public static String[] makeTargetRequestParamTypes() {
        return new String[] {
            ctypestr[V_PATH], ctypestr[V_QUERY], ctypestr[V_BODY], ctypestr[V_HEADER]
        };
    }

    //
    //
    String QUOTE(String t) {
        if (t == null || t.isEmpty()) {
            return "";
        }
        return "\"" + t + "\"";
    }

    String QUOTE_PREFCOMMA(String t) {
        String q = QUOTE(t);
        if (q != null && !q.isEmpty()) {
            return "," + q;
        }
        return "";
    }

    public void setresURL(String _url) {
        if (_url == null) _url = "";
        resURL = _url.trim();
        try {
            Pattern_resURL = ParmGenUtil.Pattern_compile(resURL);
        } catch (Exception e) {
            Pattern_resURL = null;
            LOGGER4J.error("ERROR: setresURL ", e);
        }
    }

    public String getresURL() {
        return resURL;
    }

    public Pattern getPattern_resURL() {
        return Pattern_resURL;
    }

    public Pattern getPattern_resRegex() {
        return Pattern_resRegex;
    }

    /**
     * get regex pattern for conditional parameter tracking
     *
     * @return
     */
    public Pattern getPattern_condRegex() {
        return Pattern_condRegex;
    }

    public String getresRegex() {
        return resRegex;
    }

    public void setresRegexURLencoded(String _regex) {
        if (_regex == null) _regex = "";
        setresRegex(ParmGenUtil.URLdecode(_regex, JSONFileIANACharsetName));
    }

    public void setresRegex(String _regex) {
        if (_regex == null) _regex = "";
        resRegex = _regex;
        try {
            Pattern_resRegex = ParmGenUtil.Pattern_compile(resRegex);
        } catch (Exception e) {
            LOGGER4J.error("ERROR: setresRegex ", e);
            Pattern_resRegex = null;
        }
    }

    /**
     * set regex pattern for conditional parameter tracking
     *
     * @param _regex
     */
    public void setCondRegex(String _regex) {
        if (_regex == null) _regex = "";
        this.condRegex = _regex;
        try {
            this.Pattern_condRegex = ParmGenUtil.Pattern_compile(this.condRegex);
        } catch (Exception e) {
            LOGGER4J.error("ERROR: setcondRegex ", e);
            this.Pattern_condRegex = null;
        }
    }

    public String getCondRegex() {
        return condRegex;
    }

    public void setCondRegexURLencoded(String _regex) {
        if (_regex == null) _regex = "";
        setCondRegex(ParmGenUtil.URLdecode(_regex, JSONFileIANACharsetName));
    }

    /**
     * get conditinal target request No.
     *
     * @return
     */
    public int getCondTargetNo() {
        return condTargetNo;
    }

    /**
     * set conditinal target request No.
     *
     * @param nstr String - String of number representation. specialcase is "*" or "" => -1
     */
    public void setCondTargetNo(String nstr) {
        if (nstr == null || nstr.isEmpty() || nstr.equals("*")) {
            condTargetNo = -1;
        } else {
            try {
                condTargetNo = Integer.parseInt(nstr);
            } catch (Exception e) {
                condTargetNo = -1;
            }
        }
    }

    public void setCondTargetNo(int no) {
        condTargetNo = no;
    }

    /** condition parameter tracking is exist */
    public boolean hasCond() {
        return Pattern_condRegex != null && condTargetNo != -1;
    }

    /**
     * Whether the conditional regular expression applies to requests or responses
     *
     * @return true - applies to request.
     */
    public boolean requestIsCondRegexTarget() {
        return condRegexTargetIsRequest;
    }

    /**
     * set conditional reqular expression target which is request or not.
     *
     * @param b
     */
    public void setRequestIsCondTegexTarget(boolean b) {
        condRegexTargetIsRequest = b;
    }

    /**
     * get replaceZeroSize boolean. if this value true, then request parameter replace even if
     * tracking value is zero size string.
     *
     * @return
     */
    public boolean isReplaceZeroSize() {
        return this.replaceZeroSize;
    }

    /**
     * set replaceZeroSize boolean. if this value true, then request parameter replace even if
     * tracking value is zero size string.
     *
     * @param b
     */
    public void setReplaceZeroSize(boolean b) {
        this.replaceZeroSize = b;
    }

    public void setresPartType(String respart) {
        if (respart == null) respart = "";
        resPartType = parseValPartType(respart);
    }

    /**
     * Get resRegexPos value
     *
     * @return
     */
    public int getResRegexPos() {
        return this.resRegexPos;
    }

    /**
     * Set resRegexPos value
     *
     * @param resRegexPos
     */
    public void setResRegexPos(int resRegexPos) {
        this.resRegexPos = resRegexPos;
    }

    /**
     * Set String number to resRegexPos
     *
     * @param _resregexpos
     */
    public void setResRegexPosFromString(String _resregexpos) {
        this.resRegexPos = Integer.parseInt(_resregexpos);
    }

    public int getTypeInt() {
        return valparttype & C_VTYPE;
    }

    public void setTypeInt(int t) {
        valparttype = t;
    }

    public int getResTypeInt() {
        return resPartType & C_VTYPE;
    }

    public String getAppValueDsp(int _typeval) {
        String avrec =
                QUOTE(
                                getValPart()
                                        + (isEnabled() ? "" : "+")
                                        + (isNoCount() ? "" : "+")
                                        + (_typeval == AppParmsIni.T_CSV
                                                ? ":" + Integer.toString(csvpos)
                                                : ""))
                        + ","
                        + QUOTE(value)
                        + QUOTE_PREFCOMMA(resURL)
                        + QUOTE_PREFCOMMA(resRegex)
                        + QUOTE_PREFCOMMA(getResValPart())
                        + (resRegexPos != -1 ? QUOTE_PREFCOMMA(Integer.toString(resRegexPos)) : "")
                        + QUOTE_PREFCOMMA(token)
                        + (_typeval == AppParmsIni.T_TRACK
                                ? QUOTE_PREFCOMMA(urlencode == true ? "true" : "false")
                                : "")
                        + (_typeval == AppParmsIni.T_TRACK
                                ? QUOTE_PREFCOMMA(Integer.toString(fromStepNo))
                                : "")
                        + (_typeval == AppParmsIni.T_TRACK
                                ? QUOTE_PREFCOMMA(Integer.toString(toStepNo))
                                : "")
                        + QUOTE_PREFCOMMA(tokentype.name());

        return avrec;
    }

    String getValPart() {
        return getValPart(valparttype);
    }

    public String getValPart(int _valparttype) {
        int i = _valparttype & C_VTYPE;
        if (i < C_VTYPE) {
            if (ctypestr[i] != null) return ctypestr[i];
        }
        return "";
    }

    public void setTokenTypeName(String tknames) {
        tokentype = parseTokenTypeName(tknames);
    }

    public static TokenTypeNames parseTokenTypeName(String tkname) {
        if (tkname != null && !tkname.isEmpty()) {
            String uppername = tkname.toUpperCase();
            TokenTypeNames[] tktypearray = TokenTypeNames.values();
            for (TokenTypeNames tktype : tktypearray) {
                if (tktype.name().toUpperCase().equals(uppername)) {
                    return tktype;
                }
            }
        }
        return TokenTypeNames.DEFAULT;
    }

    String getResValPart() {
        return getValPart(resPartType);
    }

    public static int parseValPartType(String _valtype) {
        int _valparttype = 0;
        String[] ivals = _valtype.split(":");
        String valtypewithflags = ivals[0];
        String _ctypestr = valtypewithflags.replaceAll("[^0-9a-zA-Z]", ""); // 英数字以外を除去
        for (int i = 1; ctypestr[i] != null; i++) {
            if (_ctypestr.equalsIgnoreCase(ctypestr[i])) {
                _valparttype = i;
                break;
            }
        }
        return _valparttype;
    }

    public boolean setValPart(String _valtype) {
        boolean noerror = false;
        valparttype = parseValPartType(_valtype);
        //
        if (_valtype.indexOf("+") != -1) { // increment
            clearNoCount();
        } else {
            setNoCount();
        }
        valpart = _valtype;
        String[] ivals = _valtype.split(":");
        csvpos = -1;
        if (ivals.length > 1) {
            csvpos = Integer.parseInt(ivals[1].trim());
        }
        if (getTypeInt() > 0) {
            noerror = true;
        }
        return noerror;
    }

    void setNoCount() {
        valparttype = valparttype | C_NOCOUNT;
    }

    public void clearNoCount() {
        valparttype = valparttype & ~C_NOCOUNT;
    }

    public boolean isNoCount() {
        return ((valparttype & C_NOCOUNT) == C_NOCOUNT ? true : false);
    }

    public boolean setURLencodedVal(String _value) {
        boolean noerror = false;
        valueregex = null;
        try {
            value = URLDecoder.decode(_value, JSONFileIANACharsetName);
            valueregex = ParmGenUtil.Pattern_compile(value);
            noerror = true;
        } catch (UnsupportedEncodingException e) {
            LOGGER4J.error("decode failed value:[" + _value + "]", e);
            valueregex = null;
        }

        return noerror;
    }

    void setVal(String _value) {
        valueregex = null;
        value = _value;
        if (value != null) {
            valueregex = ParmGenUtil.Pattern_compile(value);
        }
    }

    String getVal() {
        return value;
    }

    String[] replaceContents(
            ParmGenMacroTrace pmt,
            int currentStepNo,
            AppParmsIni pini,
            String contents,
            String org_contents_iso8859,
            ParmGenHashMap errorhash) {
        if (contents == null) return null;
        if (valueregex == null) return null;
        ParmGenTokenKey tk = null;
        if (toStepNo >= 0) {
            if (toStepNo != EnvironmentVariables.TOSTEPANY) {
                if (currentStepNo != toStepNo) {
                    return null; //
                }
                // tokentype 固定。tokentypeは追跡元のタイプなので、追跡先toStepNoの埋め込み先タイプとは無関係で無視する。
                // tk = new ParmGenTokenKey(AppValue.TokenTypeNames.DEFAULT, token, toStepNo);
                tk =
                        new ParmGenTokenKey(
                                TokenTypeNames.DEFAULT,
                                token,
                                currentStepNo); // token: tracking param name, currentStepNo: target
                // request StepNo
            } else {
                // ParmVars.plog.debuglog(0, "replaceContents toStepNo==TOSTEPANY " + toStepNo + "
                // ==" + ParmVars.TOSTEPANY);
            }
        } else {
            // ParmVars.plog.debuglog(0, "replaceContents toStepNo<0 " + toStepNo + "<0 TOSTEPANY="
            // + ParmVars.TOSTEPANY);
        }

        String[] nv = new String[2];

        String errKeyName =
                "TypeVal:"
                        + Integer.toString(pini.getTypeVal())
                        + " TargetPart:"
                        + getValPart()
                        + " TargetRegex:"
                        + value
                        + " ResRegex:"
                        + resRegex
                        + " TokenName:"
                        + token;
        ParmGenTokenKey errorhash_key = new ParmGenTokenKey(TokenTypeNames.DEFAULT, errKeyName, 0);
        Matcher m = valueregex.matcher(contents); // embed target match
        Matcher m_org = null;

        if (org_contents_iso8859 != null) {
            m_org = valueregex.matcher(org_contents_iso8859);
        }

        String newcontents = "";
        String tailcontents = "";
        String o_newcontents = "";
        String o_tailcontents = "";
        String strcnt = null;
        int cpt = 0;
        int o_cpt = 0;

        while (m.find()) {
            int spt = -1;
            int ept = -1;
            int o_spt = -1;
            int o_ept = -1;
            int gcnt = m.groupCount();
            String matchval = null;
            for (int n = 0; n < gcnt; n++) {
                spt = m.start(n + 1);
                ept = m.end(n + 1);
                matchval = m.group(n + 1);
            }
            String org_matchval = null;
            if (m_org != null) {
                if (m_org.find()) {
                    int org_gcnt = m_org.groupCount();
                    for (int n = 0; n < org_gcnt; n++) {
                        o_spt = m_org.start(n + 1);
                        o_ept = m_org.end(n + 1);
                        org_matchval = m_org.group(n + 1);
                    }
                }
            }

            if (spt != -1 && ept != -1) {
                strcnt =
                        pini.getStrCnt(pmt, this, tk, currentStepNo, toStepNo, valparttype, csvpos);
                boolean isnull = false;
                ParmGenTokenValue errorhash_value = null;
                String org_newval = strcnt;
                if (org_matchval != null) {
                    ParmGenStringDiffer differ = new ParmGenStringDiffer(org_matchval, matchval);
                    LOGGER4J.debug("org_matchval[" + org_matchval + "] matchval[" + matchval + "]");
                    strcnt = differ.replaceOrgMatchedValue(strcnt);
                }
                if (strcnt != null
                        && (!strcnt.isEmpty() || strcnt.isEmpty() && this.isReplaceZeroSize())) {
                    LOGGER4J.info(
                            java.text.MessageFormat.format(
                                    bundle.getString("ParmGen.parameter_regex_msg1.text"),
                                    new Object[] {pmt.getStepNo(), token, matchval, strcnt, value}));
                    //
                    pmt.addComments(
                            java.text.MessageFormat.format(
                                    bundle.getString("ParmGen.parameter_regex_msg2.text"),
                                    new Object[] {pmt.getStepNo(), token, matchval, strcnt, value}));
                    errorhash_value = new ParmGenTokenValue("", strcnt, true);
                    errorhash.put(errorhash_key, errorhash_value);
                } else {
                    LOGGER4J.warn(
                            java.text.MessageFormat.format(
                                    bundle.getString("ParmGen.parameter_regex_err1.text"),
                                    new Object[] {pmt.getStepNo(), token, matchval, value}));
                    pmt.addComments(
                            java.text.MessageFormat.format(
                                    bundle.getString("ParmGen.parameter_regex_err2.text"),
                                    new Object[] {pmt.getStepNo(), token, matchval, value}));
                    isnull = true;
                    errorhash_value = new ParmGenTokenValue("", strcnt, false);
                    ParmGenTokenValue storederror = errorhash.get(errorhash_key);
                    if (storederror == null || storederror.getBoolean() == false) {
                        errorhash.put(errorhash_key, errorhash_value);
                    }
                }
                if (isnull) { // if
                    strcnt = matchval;
                    org_newval = org_matchval;
                }
                newcontents += contents.substring(cpt, spt) + strcnt;
                cpt = ept;
                tailcontents = contents.substring(ept);
                if (org_matchval != null) {
                    o_newcontents += org_contents_iso8859.substring(o_cpt, o_spt) + org_newval;
                    o_cpt = o_ept;
                    o_tailcontents = org_contents_iso8859.substring(o_ept);
                }
            }
        }
        newcontents = newcontents + tailcontents;
        if (newcontents.length() == 0) {
            newcontents = contents;
        }
        o_newcontents = o_newcontents + o_tailcontents;
        if (o_newcontents.length() == 0) {
            o_newcontents = org_contents_iso8859;
        }
        nv[0] = newcontents;
        nv[1] = o_newcontents;
        return nv;
    }

    /**
     * whether this object same as argument specified or not
     *
     * @param app
     * @return
     */
    public boolean isSameContents(AppValue app) {
        if (ParmGenUtil.nullableStringEquals(this.valpart, app.valpart)
                && this.valparttype == app.valparttype
                && ParmGenUtil.nullableStringEquals(this.value, app.value)
                && this.csvpos == app.csvpos
                && ParmGenUtil.nullableStringEquals(this.resURL, app.resURL)
                && ParmGenUtil.nullableStringEquals(this.resRegex, app.resRegex)
                && this.resPartType == app.resPartType
                && this.resRegexPos == app.resRegexPos
                && ParmGenUtil.nullableStringEquals(this.token, app.token)
                && this.tokentype == app.tokentype
                && this.urlencode == app.urlencode
                && this.resencodetype == app.resencodetype
                && this.fromStepNo == app.fromStepNo
                && this.toStepNo == app.toStepNo
                && ParmGenUtil.nullableStringEquals(this.condRegex, app.condRegex)
                && this.condTargetNo == app.condTargetNo
                && this.condRegexTargetIsRequest == app.condRegexTargetIsRequest) {
            return true;
        }
        return false;
    }
}
