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

import java.net.HttpCookie;
import java.util.*;
import java.util.stream.Collectors;
import org.zaproxy.zap.extension.automacrobuilder.GSONSaveObject.PRequestResponses;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.mdepend.ClientDependent;
import org.zaproxy.zap.extension.automacrobuilder.mdepend.ClientRequest;

/** @author daike */
public class ParmGenMacroTrace extends ClientDependent {

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    // private LockInstance locker = null;

    MacroBuilderUI ui = null;

    // ============== instance unique members(copy per thread) BEGIN ==========

    private List<PRequestResponse> rlist = null; // マクロ実行後の全リクエストレスポンス
    private List<PRequestResponse> originalrlist = null; // オリジナルリクエストレスポンス

    int selected_request = 0; // 現在選択しているカレントのリクエスト

    private FetchResponseVal fetchResVal = null; // token cache  has DeepCloneable

    private ParmGenCookieManager cookieMan = null; // cookie manager has DeepCloneable

    PRequestResponse toolbaseline = null; // single shot request tool  baseline request
    // such as Repeater. when mutithread scan, this parameter is null.

    // ============== instance unique members(copy per thread) END ==========

    private Map<Integer, PRequestResponse> savelist = null; // scannned requestresponse results.

    long threadid = -1; // thread id

    PRequestResponse postmacro_RequestResponse =
            null; // after startPostMacro, this value has last RequestResponse.

    ListIterator<PRequestResponse> oit = null; // オリジナル
    ListIterator<PRequestResponse> cit = null; // 実行

    boolean MBCookieUpdate = false; // ==true Cookie更新
    boolean MBCookieFromJar = false; // ==true 開始時Cookie.jarから引き継ぐ
    boolean MBFinalResponse = false; // ==true 結果は最後に実行されたマクロのレスポンス
    boolean MBResetToOriginal = false; // ==true オリジナルリクエストを実行。
    boolean MBsettokencache = false; // 開始時tokenキャッシュ
    boolean MBreplaceCookie = false; // ==true Cookie引き継ぎ置き換え == false Cookie overwrite
    boolean MBmonitorofprocessing = false;
    boolean MBreplaceTrackingParam = false;

    int state = PMT_POSTMACRO_NULL;
    // int state possible values
    public static final int PMT_PREMACRO_BEGIN = 0; // 前処理マクロ実行中
    public static final int PMT_PREMACRO_END = 1; // 前処理マクロ実行中
    public static final int PMT_CURRENT_BEGIN = 2; // カレントリクエスト開始
    public static final int PMT_CURRENT_END = 3; // カレントリクエスト終了。
    public static final int PMT_POSTMACRO_BEGIN = 4; // 後処理マクロ実行中
    public static final int PMT_POSTMACRO_END = 5; // 後処理マクロ終了。
    public static final int PMT_POSTMACRO_NULL = 6; // 後処理マクロレスポンスnull

    private int stepno = -1; // current running request step no.

    private int last_stepno = -1; // postmacro request performs until this step no.

    private ParmGenTWait TWaiter = null;
    private int waittimer = 0; // 実行間隔(msec)

    public static ClientRequest clientrequest = new ClientRequest();

    private Object sender = null;

    public String state_debugprint() {
        String msg = "PMT_UNKNOWN";
        switch (state) {
            case PMT_PREMACRO_BEGIN:
                msg = "PMT_PREMACRO_BEGIN";
                break;
            case PMT_PREMACRO_END:
                msg = "PMT_PREMACRO_END";
                break;
            case PMT_CURRENT_BEGIN:
                msg = "PMT_CURRENT_BEGIN";
                break;
            case PMT_CURRENT_END:
                msg = "PMT_CURRENT_END";
                break;
            case PMT_POSTMACRO_BEGIN:
                msg = "PMT_POSTMACRO_BEGIN";
                break;
            case PMT_POSTMACRO_END:
                msg = "PMT_POSTMACRO_END";
                break;
            case PMT_POSTMACRO_NULL:
                msg = "PMT_POSTMACRO_NULL";
                break;
            default:
                break;
        }

        return msg;
    }

    public ParmGenMacroTrace() {}

    /**
     * Get copy of this instance for scan
     *
     * @return
     */
    public <T> ParmGenMacroTrace getScanInstance(T sender, ParmGenMacroTraceParams pmtParams) {
        ParmGenMacroTrace nobj = new ParmGenMacroTrace();
        nobj.sender = sender;
        nobj.threadid = Thread.currentThread().getId();
        // nobj.setUUID(UUIDGenerator.getUUID()); // already set in super.constructor
        nobj.rlist = this.rlist; // reference
        nobj.originalrlist = this.originalrlist; // reference
        nobj.selected_request = pmtParams.getSelectedRequestNo(); // specified scan target request
        nobj.last_stepno =
                pmtParams.getLastStepNo() == -1 ? nobj.rlist.size() - 1 : pmtParams.getLastStepNo();
        nobj.fetchResVal = this.fetchResVal != null ? this.fetchResVal.clone() : null; // deepclone
        nobj.cookieMan = this.cookieMan != null ? this.cookieMan.clone() : null; // deepclone
        nobj.savelist = new HashMap<>();
        nobj.toolbaseline = this.toolbaseline != null ? this.toolbaseline.clone() : null;
        nobj.MBCookieUpdate = this.MBCookieUpdate; // ==true Cookie更新
        nobj.MBCookieFromJar = this.MBCookieFromJar; // ==true 開始時Cookie.jarから引き継ぐ
        nobj.MBFinalResponse = this.MBFinalResponse; // ==true 結果は最後に実行されたマクロのレスポンス
        nobj.MBResetToOriginal = this.MBResetToOriginal; // ==true オリジナルリクエストを実行。
        nobj.MBsettokencache = this.MBsettokencache; // 開始時tokenキャッシュ
        nobj.MBreplaceCookie =
                this.MBreplaceCookie; // ==true Cookie引き継ぎ置き換え == false Cookie overwrite
        nobj.MBmonitorofprocessing = this.MBmonitorofprocessing;
        nobj.MBreplaceTrackingParam = this.MBreplaceTrackingParam;

        nobj.waittimer = this.waittimer;

        return nobj;
    }

    //
    // setter
    //
    public void clear() {
        ParmGen.clearAll();
        macroEnded();
        rlist = null;
        originalrlist = null;
        // REMOVE set_cookienames = null;
        selected_request = 0;
        stepno = -1;
        oit = null;
        cit = null;
        postmacro_RequestResponse = null;
        nullfetchResValAndCookieMan();
    }

    public void setUI(MacroBuilderUI _ui) {
        ui = _ui;
    }

    public void setMBCookieFromJar(boolean b) {
        MBCookieFromJar = b;
    }

    public void setMBFinalResponse(boolean b) {
        MBFinalResponse = b;
    }

    public void setMBResetToOriginal(boolean b) {
        MBResetToOriginal = b;
    }

    public void setMBsettokencache(boolean b) {
        MBsettokencache = b;
    }

    public void setMBreplaceCookie(boolean b) {
        MBreplaceCookie = b;
    }

    public void setMBmonitorofprocessing(boolean b) {
        MBmonitorofprocessing = b;
    }

    public boolean isMBmonitorofprocessing() {
        return MBmonitorofprocessing;
    }

    public void setMBreplaceTrackingParam(boolean _b) {
        MBreplaceTrackingParam = _b;
    }

    public boolean isBaseLineMode() {
        return !MBreplaceTrackingParam;
    }

    boolean isOverWriteCurrentRequestTrackigParam() {
        return !MBreplaceTrackingParam && isCurrentRequest();
    }

    public void setWaitTimer(String msec) {
        try {
            waittimer = Integer.parseInt(msec); // msec
            if (waittimer <= 0) waittimer = 0;
        } catch (Exception e) {
            waittimer = 0;
        }
    }

    // ３）カレントリクエスト終了(レスポンス受信後)後に実行
    public void endAfterCurrentRequest(PRequestResponse pqrs) {
        if (rlist != null && selected_request < rlist.size() && selected_request >= 0) {
            pqrs.setComments(getComments());
            pqrs.setError(isError());
            // rlist.set(selected_request, pqrs);
            this.savelist.put(stepno, pqrs);
        }
        // ui.updateCurrentReqRes();
        state = PMT_CURRENT_END;
    }

    /**
     * Set Current Request position number in PRequestResponse list(rlist)
     *
     * @param _p position number(from 0 to rlist.size()-1)
     */
    public void setCurrentRequest(int _p) {
        if (rlist != null && rlist.size() > _p) {
            selected_request = _p;
            EnableRequest(_p); // カレントリクエストは強制
            LOGGER4J.debug("selected_request:" + selected_request + " rlist.size=" + rlist.size());
        }
    }

    boolean isCurrentRequest(int _p) {
        if (selected_request == _p) {
            return true;
        }
        return false;
    }

    public boolean isCurrentRequest() {
        return isCurrentRequest(stepno);
    }

    public void EnableRequest(int _idx) {
        if (rlist != null && rlist.size() > _idx) {
            PRequestResponse prr = rlist.get(_idx);
            prr.Enable();
        }
    }

    public void DisableRequest(int _idx) {
        if (rlist != null && rlist.size() > _idx) {
            PRequestResponse prr = rlist.get(_idx);
            prr.Disable();
        }
    }

    boolean isDisabledRequest(int _idx) {
        if (rlist != null && rlist.size() > _idx) {
            PRequestResponse prr = rlist.get(_idx);
            return prr.isDisabled();
        }
        return false;
    }

    boolean isError(int _idx) {
        if (rlist != null && rlist.size() > _idx) {
            PRequestResponse prr = rlist.get(_idx);
            return prr.isError();
        }
        return false;
    }

    public int getRlistCount() {
        if (rlist == null) return 0;
        return rlist.size();
    }

    /**
     * update original requestlist with parameter
     *
     * @param idx
     * @param _request
     */
    public void updateOriginalRequest(int idx, PRequest _request) {
        if (originalrlist != null && idx > -1 && idx < originalrlist.size()) {
            PRequestResponse pqr = originalrlist.get(idx);
            pqr.updateRequest(_request);
            // originalrlist.set(idx, pqr);
        }
    }

    /**
     * update requestlist with paramter.
     *
     * @param idx
     * @param request
     */
    public void updateRequestCurrentList(int idx, PRequest request) {
        if (rlist != null && idx > -1 && idx < rlist.size()) {
            PRequestResponse pqr = rlist.get(idx);
            pqr.updateRequest(request);
        }
    }

    public PRequestResponse getOriginalRequest(int idx) {
        if (originalrlist != null
                && originalrlist.size() > 0
                && idx > -1
                && idx < originalrlist.size()) {
            PRequestResponse pqr = originalrlist.get(idx);
            return pqr;
        }
        return null;
    }

    PRequestResponse getCurrentOriginalRequest() {
        return getOriginalRequest(getCurrentRequestPos());
    }

    // １）前処理マクロ開始
    public void startBeforePreMacro(OneThreadProcessor otp) {
        macroStarted();

        this.savelist.clear();

        if (waittimer > 0) {
            TWaiter = new ParmGenTWait(waittimer);
        } else {
            TWaiter = null;
        }

        initFetchResponseVal();
        initCookieManager();

        if (!MBsettokencache) {
            if (fetchResVal != null) {
                fetchResVal.clearCachedLocVal();
            }
        }
        if (!MBCookieFromJar) {
            if (cookieMan != null) {
                cookieMan.removeAll();
            }
        }
        if (fetchResVal != null) {
            fetchResVal.clearDistances();
        }
        state = PMT_PREMACRO_BEGIN;
        LOGGER4J.debug("BEGIN PreMacro X-THREAD:" + threadid);

        oit = null;
        cit = null;

        stepno = 0;

        try {
            if (rlist != null && selected_request >= 0 && rlist.size() > selected_request) {
                oit = originalrlist.listIterator();
                cit = rlist.listIterator();
                int n = 0;
                if (TWaiter != null) {
                    TWaiter.TWait();
                }
                while (cit.hasNext() && oit.hasNext()) {
                    // copy clone.
                    PRequestResponse ppr = cit.next().clone();
                    PRequestResponse opr = oit.next().clone();
                    stepno = n;
                    if (n++ >= selected_request) {
                        break;
                    }

                    if (ppr.isDisabled()) {
                        continue;
                    }

                    if (MBResetToOriginal) {
                        ppr = opr; // オリジナルにリセット
                    }

                    // Set Cookie Value from CookieStore.
                    ppr.request.setCookiesFromCookieMan(cookieMan);

                    String noresponse = "";

                    LOGGER4J.debug(
                            "PreMacro StepNo:"
                                    + stepno
                                    + " "
                                    + ppr.request.getHost()
                                    + " "
                                    + ppr.request.method
                                    + " "
                                    + ppr.request.url);

                    // ppr.request.setUUID2CustomHeader(this.getUUID());
                    setUUID2CustomHeader(ppr.request);
                    // PRequestResponse pqrs = clientHttpRequest(ppr.request);
                    PRequestResponse pqrs = clientrequest.clientRequest(this, ppr.request);

                    if (pqrs != null) {
                        // cit.set(pqrs); // 更新
                        savelist.put(stepno, pqrs);
                    }

                    if (TWaiter != null) {
                        TWaiter.TWait();
                    }
                }
            }
        } catch (Exception e) {
            otp.setAborted();
            LOGGER4J.error("Exception occrued X-Thread:" + threadid, e);
        }
        LOGGER4J.debug("END PreMacro X-Thread:" + threadid);
        state = PMT_PREMACRO_END;
    }

    PRequest configureRequest(PRequest preq) {
        if (isRunning()) { // MacroBuilder list > 0 && state is Running.
            // preq.setUUID2CustomHeader(this.getUUID());
            setUUID2CustomHeader(preq);
            // ここでリクエストのCookieをCookie.jarで更新する。
            String domain_req = preq.getHost().toLowerCase();
            String path_req = preq.getPath();
            boolean isSSL_req = preq.isSSL();
            List<HttpCookie> cklist = cookieMan.get(domain_req, path_req, isSSL_req);
            HashMap<CookieKey, ArrayList<CookiePathValue>> cookiemap =
                    new HashMap<CookieKey, ArrayList<CookiePathValue>>();
            for (HttpCookie cookie : cklist) {
                String domain = cookie.getDomain();
                if (domain == null || domain.isEmpty()) {
                    domain = domain_req;
                }
                domain = domain.toLowerCase();
                if (!domain.equals(domain_req)) { // domain:.test.com != domain_req:www.test.com
                    if (domain_req.endsWith(
                            domain)) { // domain_req is belong to domain's subdomain.
                        domain = domain_req;
                    }
                }
                String name = cookie.getName();
                if (name == null) name = "";
                String path = cookie.getPath();
                if (path == null) path = "";
                String value = cookie.getValue();
                if (value == null) value = "";
                CookieKey cikey = new CookieKey(domain, name);
                LOGGER4J.debug("Cookiekey domain:" + domain + " name=" + name);
                CookiePathValue cpvalue = new CookiePathValue(path, value);
                ArrayList<CookiePathValue> cpvlist = cookiemap.get(cikey);
                if (cpvlist == null) {
                    cpvlist = new ArrayList<CookiePathValue>();
                }

                cpvlist.add(cpvalue);

                cookiemap.put(cikey, cpvlist);
            }

            boolean ReplaceCookieflg = true;
            if (isCurrentRequest()) {
                ReplaceCookieflg = MBreplaceCookie;
            }

            if (preq.setCookies(cookiemap, ReplaceCookieflg)) {}
            // This function when preq modified then he must return non null.
            // e.g. preq.setThreadId2CustomHeader(threadid) modify preq's header.
            return preq;
        }

        return null;
    }

    // ４）後処理マクロの開始
    public void startPostMacro(OneThreadProcessor otp) {
        state = PMT_POSTMACRO_BEGIN;
        postmacro_RequestResponse = null;
        if (selected_request < last_stepno) {
            // 後処理マクロ　selected_request+1 ～last_stepnoまで実行。
            stepno = selected_request + 1;
            LOGGER4J.debug("BEGIN PostMacro X-Thread:" + threadid);
            try {
                if (cit != null && oit != null) {
                    int n = stepno;
                    while (cit.hasNext() && oit.hasNext()) {
                        if (n > last_stepno) break;
                        stepno = n;
                        if (TWaiter != null) {
                            TWaiter.TWait();
                        }
                        n++;

                        PRequestResponse ppr = cit.next().clone();
                        PRequestResponse opr = oit.next().clone();
                        if (ppr.isDisabled()) {
                            continue;
                        }
                        postmacro_RequestResponse = null;
                        if (MBResetToOriginal) {
                            ppr = opr;
                        }

                        LOGGER4J.debug(
                                "PostMacro StepNo:"
                                        + stepno
                                        + " "
                                        + ppr.request.getHost()
                                        + " "
                                        + ppr.request.method
                                        + " "
                                        + ppr.request.url
                                        + " X-Thread:"
                                        + threadid);
                        // ppr.request.setUUID2CustomHeader(this.getUUID());
                        setUUID2CustomHeader(ppr.request);
                        // PRequestResponse pqrs = clientHttpRequest(ppr.request);
                        PRequestResponse pqrs = clientrequest.clientRequest(this, ppr.request);
                        if (pqrs != null) {
                            postmacro_RequestResponse = pqrs;
                            // cit.set(pqrs); // 更新
                            this.savelist.put(stepno, pqrs);
                        }
                    }
                }
            } catch (Exception ex) {
                otp.setAborted();
                LOGGER4J.error("Exception occur X-Thread:" + threadid, ex);
            }
        }
        cit = null;
        if (postmacro_RequestResponse != null) {
            state = PMT_POSTMACRO_END;
        } else {
            state = PMT_POSTMACRO_NULL;
        }

        LOGGER4J.debug("END PostMacro X-Thread:" + threadid);
    }

    byte[] getPostMacroRequest() {
        if (postmacro_RequestResponse != null) {
            return postmacro_RequestResponse.request.getByteMessage();
        }
        return null;
    }

    public byte[] getPostMacroResponse() {
        if (postmacro_RequestResponse != null) {
            return postmacro_RequestResponse.response.getByteMessage();
        }
        return null;
    }

    public PResponse getPostMacroPResponse() {
        if (postmacro_RequestResponse != null) {
            return postmacro_RequestResponse.response;
        }
        return null;
    }

    public int getCurrentRequestPos() {
        return selected_request;
    }

    boolean isRunning() {
        if (rlist != null && rlist.size() > 0) return state < PMT_POSTMACRO_END ? true : false;
        return false;
    }

    boolean CurrentRequestIsTrackFromTarget(AppParmsIni pini) {
        int FromStepNo = pini.getTrackFromStep();
        if (FromStepNo < 0) {
            return true;
        } else if (FromStepNo == stepno) {
            return true;
        }
        return false;
    }

    boolean CurrentRequestIsSetToTarget(AppParmsIni pini) {
        int ToStepNo = pini.getSetToStep();
        int ToStepBase = ParmVars.TOSTEPANY;

        if (ToStepNo == ToStepBase) {
            return true;
        } else if (ToStepNo == stepno) {
            return true;
        }
        // ParmVars.plog.debuglog(0, "!!!!!!!!!!!!!!!!! failed CurrentRequestIsSetToTarget: stepno="
        // + stepno + " ToStepNo=" + ToStepNo + " ToStepBase=" + ToStepBase) ;
        return false;
    }

    public void setRecords(List<PRequestResponse> _rlist) {
        // rlist = new ArrayList <PRequestResponse> (_rlist);//copy
        if (rlist == null) {
            rlist = _rlist; // reference共有
            originalrlist = ListDeepCopy.listDeepCopyPRequestResponse(_rlist); // Must Do Deep Copy
        } else {
            originalrlist.addAll(ListDeepCopy.listDeepCopyPRequestResponse(_rlist));
        }
        LOGGER4J.debug("setRecords:" + rlist.size() + "/" + originalrlist.size());
    }

    /**
     * Update OriginalBase
     *
     * @param pmt
     */
    public void updateOriginalBase(ParmGenMacroTrace pmt) {
        int osiz = this.rlist != null ? this.rlist.size() : 0;
        int ssiz = pmt.savelist != null ? pmt.savelist.size() : 0;

        if (ssiz > 0) {
            List<Map.Entry<Integer, PRequestResponse>> listents =
                    pmt.savelist.entrySet().stream()
                            .sorted(Map.Entry.comparingByKey())
                            .collect(Collectors.toList());
            if (this.rlist == null) {
                this.rlist = new ArrayList<>();
            }

            listents.forEach(
                    ent -> {
                        int i = ent.getKey();
                        if (i < this.rlist.size()) {
                            this.rlist.set(i, ent.getValue());
                        }
                    });

            // so update is omitted.
            this.ui.updaterlist(this.rlist);
            // private FetchResponseVal fetchResVal = null; // token cache  has DeepCloneable
            this.fetchResVal = pmt.fetchResVal;
            // private ParmGenCookieManager cookieMan = null; // cookie manager has DeepCloneable
            this.cookieMan = pmt.cookieMan;
            // PRequestResponse toolbaseline = null;
            this.toolbaseline = pmt.toolbaseline;
            LOGGER4J.debug("result update succeeded. size:" + ssiz);
        }
    }

    void macroStarted() {
        LOGGER4J.debug("<--Macro Started.--> X-Thread:" + threadid);
        // this.threadid = this.locker.lock();
    }

    public void macroEnded() {
        nullState();
        // this.locker.unlock(this.threadid);

        LOGGER4J.debug("<--Macro Complete Ended.--> X-Thread:" + threadid);
    }

    private void nullState() {
        state = PMT_POSTMACRO_NULL;
        stepno = -1;
        scanQueNull();
    }

    public void setToolBaseLine(PRequestResponse _baseline) {
        toolbaseline = _baseline;
    }

    public void setState(int st) {
        state = st;
    }

    //
    // getter
    //
    public int getState() {
        return state;
    }

    public long getThreadId() {
        return this.threadid;
    }

    List<PRequestResponse> getRecords() {
        return rlist;
    }

    public boolean isMBFinalResponse() {
        return MBFinalResponse;
    }

    public int getStepNo() {
        return stepno;
    }

    public PRequestResponse getToolBaseline() {
        return toolbaseline;
    }

    /**
     * get current requestresponse
     *
     * @param pos
     * @return
     */
    public PRequestResponse getRequestResponseCurrentList(int pos) {
        if (rlist != null && rlist.size() > 0) {
            PRequestResponse pqr = rlist.get(pos);
            return pqr;
        }
        return null;
    }

    /**
     * get RequestResponse current or original
     *
     * @param pos
     * @return
     */
    public PRequestResponse getRequestResponse(int pos) {
        if (rlist != null && rlist.size() > 0) {
            PRequestResponse pqr = rlist.get(pos);
            if (MBResetToOriginal) {
                pqr = originalrlist.get(pos);
            }

            return pqr;
        }
        return null;
    }

    /**
     * Get current selected PRequestResponse object from PRequstResponse list.
     *
     * @return PRequestResponse
     */
    public PRequestResponse getCurrentRequestResponse() {
        if (this.selected_request > -1) {
            return getRequestResponse(this.selected_request);
        }
        return null;
    }

    public void sendToRepeater(int pos) {
        PRequestResponse pqr = null;
        if ((pqr = getRequestResponse(pos)) != null) {
            setToolBaseLine(pqr);
            String host = pqr.request.getHost();
            int port = pqr.request.getPort();
            boolean useHttps = pqr.request.isSSL();
            ParmGenMacroTraceParams pmtParams = new ParmGenMacroTraceParams();
            pmtParams.setSelectedRequestNo(pos);
            pqr.request.setParamsCustomHeader(pmtParams);
            burpSendToRepeater(
                    host, port, useHttps, pqr.request.getByteMessage(), "MacroBuilder:" + pos);
        }
    }

    public void sendToScanner(int pos) {
        PRequestResponse pqr = null;
        if ((pqr = getRequestResponse(pos)) != null) {
            setToolBaseLine(null);
            String host = pqr.request.getHost();
            int port = pqr.request.getPort();
            boolean useHttps = pqr.request.isSSL();
            ParmGenMacroTraceParams pmtParams = new ParmGenMacroTraceParams();
            pmtParams.setSelectedRequestNo(pos);
            pqr.request.setParamsCustomHeader(pmtParams);
            burpDoActiveScan(host, port, useHttps, pqr.request.getByteMessage());
        }
    }

    public void sendToIntruder(int pos) {
        PRequestResponse pqr = null;
        if ((pqr = getRequestResponse(pos)) != null) {
            setToolBaseLine(null);
            String host = pqr.request.getHost();
            int port = pqr.request.getPort();
            boolean useHttps = pqr.request.isSSL();
            ParmGenMacroTraceParams pmtParams = new ParmGenMacroTraceParams();
            pmtParams.setSelectedRequestNo(pos);
            pqr.request.setParamsCustomHeader(pmtParams);
            burpSendToIntruder(host, port, useHttps, pqr.request.getByteMessage());
        }
    }

    void GSONSave(GSONSaveObject gsonsaveobj) {
        if (gsonsaveobj != null) {
            if (originalrlist != null) {
                gsonsaveobj.CurrentRequest = getCurrentRequestPos();

                for (PRequestResponse pqr : originalrlist) {
                    PRequestResponses preqresobj = new PRequestResponses();
                    byte[] qbin = pqr.request.getByteMessage();
                    byte[] rbin = pqr.response.getByteMessage();
                    // byte[] encodedBytes = Base64.encodeBase64(qbin);
                    String qbase64 =
                            Base64.getEncoder()
                                    .encodeToString(qbin); // same as new String(encode(src),
                    // StandardCharsets.ISO_8859_1)
                    /*
                    try {
                        qbase64 = new String(encodedBytes,"ISO-8859-1");
                    } catch (UnsupportedEncodingException ex) {
                        Logger.getLogger(ParmGenMacroTrace.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    */
                    // encodedBytes = Base64.encodeBase64(rbin);
                    String rbase64 = Base64.getEncoder().encodeToString(rbin);
                    /*
                    try {
                        rbase64 = new String(encodedBytes, "ISO-8859-1");
                    } catch (UnsupportedEncodingException ex) {
                        Logger.getLogger(ParmGenMacroTrace.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    */
                    preqresobj.PRequest = qbase64;
                    preqresobj.PResponse = rbase64;

                    String host = pqr.request.getHost();
                    int port = pqr.request.getPort();
                    boolean ssl = pqr.request.isSSL();
                    String comments = pqr.getComments();
                    boolean isdisabled = pqr.isDisabled();
                    boolean iserror = pqr.isError();
                    preqresobj.Host = host;
                    preqresobj.Port = port;
                    preqresobj.SSL = ssl;
                    preqresobj.Comments = comments == null ? "" : comments;
                    preqresobj.Disabled = isdisabled;
                    preqresobj.Error = iserror;

                    gsonsaveobj.PRequestResponse.add(preqresobj);
                }
            }
        }
    }

    public void initFetchResponseVal() {
        if (fetchResVal == null) {
            fetchResVal = new FetchResponseVal(this);
        }
    }

    public FetchResponseVal getFetchResponseVal() {
        return fetchResVal;
    }

    public void nullfetchResValAndCookieMan() {
        fetchResVal = null;
        cookieMan = null;
    }

    public void initCookieManager() {
        if (cookieMan == null) {
            cookieMan = new ParmGenCookieManager();
        }
    }

    public List<PRequestResponse> getOriginalrlist() {
        return originalrlist;
    }

    public void parseSetCookie(PRequestResponse pqrs) {
        // カレントリクエストのset-cookie値をcookie.jarに保管

        List<String> setcookieheaders = pqrs.response.getSetCookieHeaders();
        for (String headerval : setcookieheaders) {
            String cheader = "Set-Cookie: " + headerval;
            String domain = pqrs.request.getHost();
            String path = "/"; // default root path
            cookieMan.parse(domain, path, cheader);
        }
    }

    public <T> T getSender() {
        return CastUtils.castToType(this.sender);
    }
}
