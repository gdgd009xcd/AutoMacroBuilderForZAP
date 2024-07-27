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

import java.net.HttpCookie;
import java.util.*;
import java.util.stream.Collectors;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.mdepend.ClientDependent;
import org.zaproxy.zap.extension.automacrobuilder.mdepend.ClientRequest;
import org.zaproxy.zap.extension.automacrobuilder.view.StyledDocumentWithChunk;
import org.zaproxy.zap.extension.automacrobuilder.view.SwingTimerFakeRunner;

/** @author gdgd009xcd */
public class ParmGenMacroTrace extends ClientDependent {

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    // private LockInstance locker = null;

    MacroBuilderUI ui = null;

    private List<AppParmsIni> appParmsIniList = null;

    // ============== instance unique members(copy per thread) BEGIN ==========

    private List<PRequestResponse> rlist = null; // requestresponse results
    private List<PRequestResponse> originalrlist = null; // original requestresponse

    int selected_request = 0; // current selected request number

    private FetchResponseVal fetchResVal = null; // token cache  has DeepCloneable

    private CookieManager cookieMan = null; // cookie manager has DeepCloneable

    PRequestResponse toolbaseline = null; // single shot request tool  baseline request
    // such as Repeater. when mutithread scan, this parameter is null.

    // ============== instance unique members(copy per thread) END ==========

    private Map<Integer, PRequestResponse> savelist = null; // scannned requestresponse results.

    long threadid = -1; // thread id

    PRequestResponse postmacro_RequestResponse =
            null; // after startPostMacro, this value has last RequestResponse.

    ListIterator<PRequestResponse> oit = null; // iterator for resquestresponse results
    ListIterator<PRequestResponse> cit = null; // iterator for original requestresponse

    private boolean CBInheritFromCache =
            false; // == true then Cookies is updated with cache from begin.
    private boolean CBFinalResponse =
            false; // == true then scan target request's response is updated with last request's
    // response in macro request list.
    private boolean CBResetToOriginal = false; // == true use original requestresponse.
    private boolean CBreplaceCookie = false; // == true then overwrite Cookie
    private boolean CBreplaceTrackingParam = false; // == true then overwrite Tracking Tokens

    int state = PMT_POSTMACRO_NULL;
    // int state possible values
    public static final int PMT_PREMACRO_BEGIN = 0; // Started Pre Macros
    public static final int PMT_PREMACRO_END = 1; // Ended Pre Macro Running
    public static final int PMT_CURRENT_BEGIN = 2; // Started Current Target Request
    public static final int PMT_CURRENT_END = 3; // Ended Current Target Request
    public static final int PMT_POSTMACRO_BEGIN = 4; // Started Post Macros
    public static final int PMT_POSTMACRO_END = 5; // Ended Post Macros
    public static final int PMT_POSTMACRO_NULL = 6; // Completed ALL requests or stopped.

    private int stepno = -1; // current running request step no.

    private int last_stepno = -1; // postmacro request performs until this step no.

    private int tabIndex = -1; // index of Macro Request List tab in MacroBuilderUI

    private int myPageIndex =
            -1; // mypage: Request index that holds session attributes(cookies/tokens etc..)

    private String myPageResponseCache = null; // response String in mypage request

    private ParmGenTWait TWaiter = null;
    private int waittimer = 0; // wait timer (msec)

    public static ClientRequest clientrequest = new ClientRequest();

    private Object sender = null;

    private Map<Integer, List<AppValue>> cachedAppValues =
            null; // cache of AppValues. cache is valid only when running macros.

    private final Encode defaultEncode = Encode.UTF_8; // default page encoding
    private Encode sequenceEncode = defaultEncode;; // sequence encoding

    private Encode lastResponseEncode = null; // last executed response encoding

    private boolean isURIOfRequestIsModified = false;

    private boolean isCacheNull = false;

    private int runningStepNo = -1;// current running stepno. use only in base instance.

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

    public List<AppParmsIni> getAppParmsIniList() {
        return this.appParmsIniList;
    }

    public AppParmsIni getAppParmsIni(int i) {
        if (this.appParmsIniList != null && this.appParmsIniList.size() > i) {
            return this.appParmsIniList.get(i);
        }
        return null;
    }

    public Iterator<AppParmsIni> getIteratorOfAppParmsIni() {
        return this.appParmsIniList.iterator();
    }

    public void removeAppParmsIni(int i) {
        if (this.appParmsIniList != null && this.appParmsIniList.size() > i) {
            this.appParmsIniList.remove(i);
        }
    }

    /**
     * Update appParmsIniList and clear session cookies/tokens
     *
     * @param appParmsIniList
     */
    public void setAppParmsIniList(List<AppParmsIni> appParmsIniList) {
        this.appParmsIniList = appParmsIniList;
        nullfetchResValAndCookieMan(); // clear session cookies/tokens because appParmIniList is
        // updated.
    }

    public ParmGenMacroTrace() {}

    /**
     * create New running instance for scan
     *
     * @return
     */
    public <T> ParmGenMacroTrace createScanRunningInstance(
            T sender, ParmGenMacroTraceParams pmtParams, ParmGenMacroTraceProvider pmtProvider) {
        ParmGenMacroTrace nobj = new ParmGenMacroTrace();
        SwingTimerFakeRunner swingRunner = pmtProvider.getSwingRunner(pmtParams.getTabIndex());
        if (swingRunner != null) {
            swingRunner.registRunningInstance(nobj);
        }

        nobj.sender = sender;
        nobj.threadid = Thread.currentThread().getId();
        // nobj.setUUID(UUIDGenerator.getUUID()); // already set in super.constructor
        nobj.rlist = this.rlist; // reference
        nobj.originalrlist = this.originalrlist; // reference
        nobj.appParmsIniList = this.appParmsIniList; // reference
        nobj.selected_request = pmtParams.getSelectedRequestNo(); // specified scan target request
        nobj.last_stepno =
                pmtParams.getLastStepNo() == -1 ? nobj.rlist.size() - 1 : pmtParams.getLastStepNo();
        nobj.tabIndex = pmtParams.getTabIndex();
        nobj.fetchResVal = this.fetchResVal != null ? this.fetchResVal.clone() : null; // deepclone
        nobj.cookieMan = this.cookieMan != null ? this.cookieMan.clone() : null; // deepclone
        if (pmtProvider.getCBInheritFromCache()) {
            if (nobj.cookieMan == null) {
                nobj.cookieMan = new CookieManager();
            }
           nobj.cookieMan.addCookieManager(pmtProvider.getCookieManagerInAppScope());
        }
        nobj.savelist = new HashMap<>();
        nobj.toolbaseline = this.toolbaseline != null ? this.toolbaseline.clone() : null;
        nobj.CBInheritFromCache =
                pmtProvider.getCBInheritFromCache(); // ==true inherit CSRFtoken/cookie values from
        // cache
        nobj.CBFinalResponse = pmtProvider.getCBFinalResponse();
        nobj.CBResetToOriginal = pmtProvider.getCBResetToOriginal();
        nobj.CBreplaceCookie = pmtProvider.getCBreplaceCookie();
        nobj.CBreplaceTrackingParam = pmtProvider.getCBreplaceTrackingParam();

        nobj.waittimer = pmtProvider.getWaitTimer();

        nobj.cachedAppValues = null;

        nobj.myPageIndex = this.myPageIndex;

        nobj.myPageResponseCache = this.myPageResponseCache;

        nobj.sequenceEncode = this.sequenceEncode;

        nobj.lastResponseEncode = this.lastResponseEncode;

        nobj.isURIOfRequestIsModified = this.isURIOfRequestIsModified;

        nobj.isCacheNull = this.isCacheNull;

        nobj.runningStepNo = this.runningStepNo;

        return nobj;
    }

    public ParmGenMacroTrace getCopyInstanceForSession() {
        ParmGenMacroTrace nobj = new ParmGenMacroTrace();
        nobj.sender = this.sender;
        nobj.threadid = Thread.currentThread().getId();
        nobj.postmacro_RequestResponse =
                this.postmacro_RequestResponse != null
                        ? this.postmacro_RequestResponse.clone()
                        : null;
        nobj.oit = null;
        nobj.cit = null;
        // nobj.setUUID(UUIDGenerator.getUUID()); // already set in super.constructor
        nobj.rlist = this.rlist; // reference
        nobj.originalrlist = this.originalrlist; // reference
        nobj.appParmsIniList = this.appParmsIniList; // reference
        nobj.selected_request = this.selected_request; // specified scan target request
        nobj.last_stepno = this.last_stepno;
        nobj.tabIndex = this.tabIndex;
        nobj.fetchResVal = this.fetchResVal != null ? this.fetchResVal.clone() : null; // deepclone
        nobj.cookieMan = this.cookieMan != null ? this.cookieMan.clone() : null; // deepclone
        nobj.savelist = HashMapDeepCopy.hashMapDeepCopySaveList(this.savelist); // deepclone
        nobj.toolbaseline =
                this.toolbaseline != null ? this.toolbaseline.clone() : null; // deepclone
        nobj.CBInheritFromCache = this.CBInheritFromCache;

        // cache
        nobj.CBFinalResponse = this.CBFinalResponse;
        nobj.CBResetToOriginal = this.CBResetToOriginal;
        nobj.CBreplaceCookie = this.CBreplaceCookie;
        nobj.CBreplaceTrackingParam = this.CBreplaceTrackingParam;

        nobj.state = this.state;
        nobj.stepno = this.stepno;

        nobj.waittimer = this.waittimer;
        if (nobj.waittimer > 0) {
            nobj.TWaiter = new ParmGenTWait(nobj.waittimer);
        } else {
            nobj.TWaiter = null;
        }

        nobj.cachedAppValues = this.cachedAppValues;

        nobj.myPageIndex = this.myPageIndex;

        nobj.myPageResponseCache = this.myPageResponseCache;

        nobj.sequenceEncode = this.sequenceEncode;

        nobj.lastResponseEncode = this.lastResponseEncode;

        nobj.isCacheNull = this.isCacheNull;

        nobj.runningStepNo = this.runningStepNo;

        return nobj;
    }

    //
    // setter
    //
    public void clear() {
        this.cachedAppValues = null;
        this.appParmsIniList = null;
        macroEnded();
        rlist = null;
        originalrlist = null;
        // REMOVE set_cookienames = null;
        selected_request = 0;
        stepno = -1;
        oit = null;
        cit = null;
        postmacro_RequestResponse = null;
        sequenceEncode = defaultEncode;
        lastResponseEncode = null;
        isURIOfRequestIsModified = false;
        isCacheNull = false;
        runningStepNo = -1;
        nullfetchResValAndCookieMan();
    }

    public void setUI(MacroBuilderUI _ui) {
        ui = _ui;
    }

    boolean isOverWriteCurrentRequestTrackigParam() {
        return !CBreplaceTrackingParam && isCurrentRequest();
    }

    // ３）カレントリクエスト終了(レスポンス受信後)後に実行
    public void endAfterCurrentRequest(PRequestResponse pqrs) {
        if (rlist != null && selected_request < rlist.size() && selected_request >= 0) {
            pqrs.setComments(getComments());
            pqrs.setError(isError());

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

    /*
     * Enable selected request in rlist
     */
    public void EnableRequest(int _idx) {
        if (rlist != null && rlist.size() > _idx) {
            PRequestResponse prr = rlist.get(_idx);
            prr.Enable();
        }
    }

    /*
     * Disable selected request in rlist
     */
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
     * initialize cachedAppValueList which has null value.
     *
     * @return true when initialized.
     */
    boolean initializedCachedAppValues() {
        boolean b = false;
        if (this.cachedAppValues == null) {
            this.cachedAppValues = new HashMap<>();
            b = true;
        }
        return b;
    }

    /**
     * add AppValue to cache. cache is valid only when running macros.
     *
     * @param ap
     */
    void addAppValueToCache(AppValue ap) {
        if (this.cachedAppValues != null && ap != null) {
            List<AppValue> aplist = this.cachedAppValues.get(ap.getCondTargetNo());
            if (aplist == null) {
                aplist = new ArrayList<>();
            }
            aplist.add(ap);
            this.cachedAppValues.put(ap.getCondTargetNo(), aplist);
        }
    }

    /**
     * get AppValue which has specified targetno cache is valid only when running macros.
     *
     * @return AppValue
     */
    List<AppValue> getCachedAppValues(int targetno) {
        if (this.cachedAppValues != null) {
            return this.cachedAppValues.get(targetno);
        }
        return null;
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

    public PRequestResponse getOriginalPRequestResponse(int idx) {
        if (originalrlist != null
                && originalrlist.size() > 0
                && idx > -1
                && idx < originalrlist.size()) {
            PRequestResponse pqr = originalrlist.get(idx);
            return pqr;
        }
        return null;
    }

    public PRequestResponse getCurrentOriginalRequest() {
        return getOriginalPRequestResponse(getCurrentRequestPos());
    }

    // 1) Start Pre Macros
    public void startBeforePreMacro(OneThreadProcessor otp) {
        macroStarted();

        isURIOfRequestIsModified = false;

        lastResponseEncode = null;

        this.savelist.clear();

        if (waittimer > 0) {
            TWaiter = new ParmGenTWait(waittimer);
        } else {
            TWaiter = null;
        }

        boolean fetchResponseValIsNull = initFetchResponseVal();
        boolean cookieManagerIsNull = initCookieManager();
        this.isCacheNull = fetchResponseValIsNull && cookieManagerIsNull;

        if (!CBInheritFromCache) {
            if (fetchResVal != null) {
                fetchResVal.clearCachedLocVal();
            }
        }
        if (!CBInheritFromCache) {
            if (cookieMan != null) {
                cookieMan.removeAll();
            }
            clientrequest.resetCookieManager(this);// reset(clear) dependent system's cookie manager state(i.e. ZAP HttpState).
        }

        if (fetchResVal != null) {
            fetchResVal.clearDistances();
        }


        state = PMT_PREMACRO_BEGIN;
        LOGGER4J.debug("BEGIN PreMacro X-THREAD:" + threadid);

        oit = null;
        cit = null;

        this.stepno = 0;


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
                    this.stepno = n;
                    if (n++ >= selected_request) {
                        break;
                    }

                    if (ppr.isDisabled()) {
                        continue;
                    }

                    if (CBResetToOriginal) {
                        ppr = opr; // オリジナルにリセット
                    }

                    // Set Cookie Value from CookieStore.
                    ppr.request.setCookiesFromCookieMan(cookieMan);

                    String noresponse = "";

                    LOGGER4J.debug(
                            "PreMacro StepNo:"
                                    + this.stepno
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

                    lastResponseEncode = pqrs.response.getPageEnc();

                    if (pqrs != null) {
                        // cit.set(pqrs); // 更新
                        savelist.put(this.stepno, pqrs);
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

    /**
     * get PRequestResponse message from savelist
     *
     * @param no
     * @return
     */
    public PRequestResponse getPRequestResponseFromSaveList(int no) {
        if (savelist != null && savelist.size() > no) {
            return savelist.get(no);
        }
        return null;
    }

    PRequest configureRequest(PRequest preq) {
        if (isRunning()) { // MacroBuilder list > 0 && state is Running.
            // preq.setUUID2CustomHeader(this.getUUID());
            setUUID2CustomHeader(preq);
            // ここでリクエストのCookieをCookie.jarで更新する。
            String domain_req = preq.getHost().toLowerCase();
            String path_req = preq.getURIWithoutQueryPart();
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
                ReplaceCookieflg = CBreplaceCookie;
            }

            if (preq.setCookies(cookiemap, ReplaceCookieflg)) {}
            // This function when preq modified then he must return non null.
            // e.g. preq.setThreadId2CustomHeader(threadid) modify preq's header.
            return preq;
        }

        return null;
    }

    // 3) start Post Macros
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
                        if (CBResetToOriginal) {
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
                            lastResponseEncode = pqrs.response.getPageEnc();
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

    public byte[] getPostMessageResponse() {
        if (postmacro_RequestResponse != null) {
            return postmacro_RequestResponse.response.getByteMessage();
        }
        return null;
    }

    public PResponse getPostMessagePResponse() {
        if (postmacro_RequestResponse != null) {
            return postmacro_RequestResponse.response;
        }
        return null;
    }

    public int getCurrentRequestPos() {
        return selected_request;
    }

    public int getMyPageIndex() {
        return myPageIndex;
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
        int ToStepBase = EnvironmentVariables.TOSTEPANY;

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
            rlist.addAll(_rlist);
            originalrlist.addAll(ListDeepCopy.listDeepCopyPRequestResponse(_rlist));
        }
        LOGGER4J.debug("setRecords:" + rlist.size() + "/" + originalrlist.size());
    }

    /**
     * Update OriginalBase
     *
     * @param runningInstance
     */
    public void updateOriginalBase(ParmGenMacroTrace runningInstance) {
        int ssiz = runningInstance.savelist != null ? runningInstance.savelist.size() : 0;

        LOGGER4J.debug("updateOriginalBase ssiz:" + ssiz);
        if (ssiz > 0) {
            List<Map.Entry<Integer, PRequestResponse>> listents =
                    runningInstance.savelist.entrySet().stream()
                            .sorted(Map.Entry.comparingByKey())
                            .collect(Collectors.toList());
            if (this.rlist == null) {
                this.rlist = new ArrayList<>();
            }

            listents.forEach(
                    ent -> {
                        int i = ent.getKey();
                        if (i < this.rlist.size()) {
                            /**
                            List<RequestChunk> orgchunks =
                                    this.rlist
                                            .get(i)
                                            .request
                                            .generateRequestChunks(); // current display content chunks.
                            ent.getValue()
                                    .request
                                    .updateDocAndChunks(orgchunks); // update chunks if possible.
                             **/
                            this.rlist.set(i, ent.getValue());
                        }
                    });

            // below updaterlist no need execute. because UI does not have rlist.
            // this.ui.updaterlist(this.rlist);
            // private FetchResponseVal fetchResVal = null; // token cache  has DeepCloneable
            this.fetchResVal = runningInstance.fetchResVal;
            // private ParmGenCookieManager cookieMan = null; // cookie manager has DeepCloneable
            this.cookieMan = runningInstance.cookieMan;
            // PRequestResponse toolbaseline = null;
            this.toolbaseline = runningInstance.toolbaseline;
            // update selected_request maybe if runningInstance is Not made from this.
            setCurrentRequest(runningInstance.selected_request);
            LOGGER4J.debug("result update succeeded. size:" + ssiz);
        }
        if (ui != null) {
            ui.clearDisplayInfoViewFlags();
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

    public boolean isCBFinalResponse() {
        return CBFinalResponse;
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
            if (CBResetToOriginal) {
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

    public void sendToRepeater(int currentSelectedPos, int tabIndex) {
        PRequestResponse pqr = null;
        if ((pqr = getRequestResponseCurrentList(currentSelectedPos)) != null) {
            StyledDocumentWithChunk doc = ui.getStyledDocumentOfSelectedMessageRequest();
            if (doc != null) {
                PRequest prequest = doc.reBuildPRequestFromDocTextAndChunksWithEncodeCustomTag();
                if (prequest != null) {
                    pqr.updateRequest(
                            prequest.clone()); // update rlist with ui.MacroRequest contents.
                }
                setToolBaseLine(pqr);
                String host = pqr.request.getHost();
                int port = pqr.request.getPort();
                boolean useHttps = pqr.request.isSSL();
                int subSequenceScanLimit = ui.getSubSequenceScanLimit();
                int lastStepNo = getLastStepNo(currentSelectedPos, subSequenceScanLimit);
                ParmGenMacroTraceParams pmtParams =
                        new ParmGenMacroTraceParams(currentSelectedPos, lastStepNo, tabIndex);
                pqr.request.setParamsCustomHeader(pmtParams);
                burpSendToRepeater(
                        host,
                        port,
                        useHttps,
                        pqr.request.getByteMessage(),
                        "MacroBuilder:" + currentSelectedPos);
            }
        }
    }

    public void sendToScanner(int currentSelectedPos, int tabIndex) {
        PRequestResponse pqr = null;
        if ((pqr = getRequestResponseCurrentList(currentSelectedPos)) != null) {
            StyledDocumentWithChunk doc = ui.getStyledDocumentOfSelectedMessageRequest();
            if (doc != null) {
                PRequest prequest = doc.reBuildPRequestFromDocTextAndChunksWithEncodeCustomTag();
                if (prequest != null) {
                    pqr.updateRequest(
                            prequest.clone()); // update rlist with ui.MacroRequest contents.
                }
                setToolBaseLine(null);
                String host = pqr.request.getHost();
                int port = pqr.request.getPort();
                boolean useHttps = pqr.request.isSSL();
                int subSequenceScanLimit = ui.getSubSequenceScanLimit();
                int lastStepNo = getLastStepNo(currentSelectedPos, subSequenceScanLimit);
                ParmGenMacroTraceParams pmtParams =
                        new ParmGenMacroTraceParams(currentSelectedPos, lastStepNo, tabIndex);

                pqr.request.setParamsCustomHeader(pmtParams);
                burpDoActiveScan(host, port, useHttps, pqr.request.getByteMessage());
            }
        }
    }

    public void sendToIntruder(int currentSelectedPos, int tabIndex) {
        PRequestResponse pqr = null;
        if ((pqr = getRequestResponseCurrentList(currentSelectedPos)) != null) {
            StyledDocumentWithChunk doc = ui.getStyledDocumentOfSelectedMessageRequest();
            if (doc != null) {
                PRequest prequest = doc.reBuildPRequestFromDocTextAndChunksWithEncodeCustomTag();
                if (prequest != null) {
                    pqr.updateRequest(
                            prequest.clone()); // update rlist with ui.MacroRequest contents.
                }
                setToolBaseLine(null);
                String host = pqr.request.getHost();
                int port = pqr.request.getPort();
                boolean useHttps = pqr.request.isSSL();
                int subSequenceScanLimit = ui.getSubSequenceScanLimit();
                int lastStepNo = getLastStepNo(currentSelectedPos, subSequenceScanLimit);
                ParmGenMacroTraceParams pmtParams =
                        new ParmGenMacroTraceParams(currentSelectedPos, lastStepNo, tabIndex);
                pqr.request.setParamsCustomHeader(pmtParams);
                burpSendToIntruder(host, port, useHttps, pqr.request.getByteMessage());
            }
        }
    }

    /**
     * save originalrlist to JSON
     *
     * @param gsonsaveobj
     */
    @Deprecated
    void GSONSave(GSONSaveObject gsonsaveobj) {
        if (gsonsaveobj != null) {
            if (originalrlist != null) {
                gsonsaveobj.CurrentRequest = getCurrentRequestPos();

                for (PRequestResponse pqr : originalrlist) {
                    GSONSaveObject.GsonPRequestResponse preqresobj =
                            new GSONSaveObject.GsonPRequestResponse();
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
                    preqresobj.PRequest64 = qbase64;
                    preqresobj.PResponse64 = rbase64;

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

                    gsonsaveobj.PRequestResponses.add(preqresobj);
                }
            }
        }
    }

    /**
     * save sequence of PRequestResponse and it's tracking parameters to JSON
     *
     * @param appParmAndSequence
     */
    void GSONSaveV2(GSONSaveObjectV2.AppParmAndSequence appParmAndSequence) {
        if (appParmAndSequence != null) {
            if (originalrlist != null) {
                appParmAndSequence.MyPageIndex = getMyPageIndex();
                appParmAndSequence.CurrentRequest = getCurrentRequestPos();
                appParmAndSequence.sequenceCharsetName = sequenceEncode.getIANACharsetName();

                for (PRequestResponse pqr : originalrlist) {
                    GSONSaveObjectV2.GsonPRequestResponse preqresobj =
                            new GSONSaveObjectV2.GsonPRequestResponse();
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
                    preqresobj.PRequest64 = qbase64;
                    preqresobj.PResponse64 = rbase64;

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
                    preqresobj.RequestCharsetName = pqr.request.getPageEnc().getIANACharsetName();
                    preqresobj.ResponseCharsetName = pqr.response.getPageEnc().getIANACharsetName();

                    appParmAndSequence.PRequestResponses.add(preqresobj);
                }
            }
        }
    }

    public boolean initFetchResponseVal() {
        if (fetchResVal == null) {
            fetchResVal = new FetchResponseVal();
            return true;
        }
        return false;
    }

    public FetchResponseVal getFetchResponseVal() {
        return fetchResVal;
    }

    public void nullfetchResValAndCookieMan() {
        LOGGER4J.debug("nullfetchResValAndCookieMan called. cleared cookies and tokens.");
        fetchResVal = null;
        cookieMan = null;
        myPageResponseCache = null;
    }

    public boolean initCookieManager() {
        if (cookieMan == null) {
            cookieMan = new CookieManager();
            return true;
        }
        return false;
    }

    public void parseSetCookie(PRequestResponse pqrs) {
        // カレントリクエストのset-cookie値をcookie.jarに保管

        List<String> setcookieheaders = pqrs.response.getSetCookieHeaders();
        for (String headerval : setcookieheaders) {
            String cheader = "Set-Cookie: " + headerval;
            String domain = pqrs.request.getHost();
            String path = pqrs.request.getPath();
            cookieMan.parse(domain, path, cheader);
        }
    }

    public <T> T getSender() {
        return CastUtils.castToType(this.sender);
    }

    /**
     * get lasteStepNo which respresents last StepNo in RequestList.
     *
     * @param currentSelectedPos
     * @param subSequenceScanLimit
     * @return
     */
    public int getLastStepNo(int currentSelectedPos, int subSequenceScanLimit) {
        int lastStepNo = currentSelectedPos + subSequenceScanLimit;
        int rlistSize = rlist.size();
        if (lastStepNo > rlistSize || subSequenceScanLimit < 0) return -1;
        return lastStepNo;
    }

    /**
     * get index of Macro Request List tab in MacroBuilderUI
     *
     * @return
     */
    public int getTabIndex() {
        return this.tabIndex;
    }

    /**
     * get Iterator of PRequestResponse
     *
     * @return
     */
    public Iterator<PRequestResponse> getIteratorOfRlist() {
        return rlist.iterator();
    }

    public List<PRequestResponse> getPRequestResponseList() {
        return rlist;
    }

    public List<PRequestResponse> getOriginalPRequestResponseList() {
        return originalrlist;
    }

    public int getRequestListSize() {
        return rlist != null ? rlist.size() : -1;
    }

    /**
     * exchange SetToStep minpos and maxpos in parmcsv
     *
     * @param minpos
     * @param maxpos
     */
    public void exchangeStepNo(int minpos, int maxpos) {
        List<AppParmsIni> appParmsIniList = getAppParmsIniList();
        if (appParmsIniList != null && !appParmsIniList.isEmpty()) {
            appParmsIniList.stream()
                    .forEach(
                            pini_filtered -> {
                                int settostep = pini_filtered.getSetToStep();
                                if (settostep == minpos) {
                                    pini_filtered.setSetToStep(maxpos);
                                } else if (settostep == maxpos) {
                                    pini_filtered.setSetToStep(minpos);
                                }
                                int fromstep = pini_filtered.getTrackFromStep();
                                if (fromstep == minpos) {
                                    pini_filtered.setTrackFromStep(maxpos);
                                } else if (fromstep == maxpos) {
                                    pini_filtered.setTrackFromStep(minpos);
                                }
                            });
        }
    }

    /**
     * Get AppParmsIni which has stepno specified in TrackFromStep/SetToStep parameter
     *
     * @param stepno
     * @return
     */
    public List<AppParmsIni> getAppParmIniHasStepNoSpecified(int stepno) {
        List<AppParmsIni> hasnolist = new ArrayList<>();
        List<AppParmsIni> appParmsIniList = getAppParmsIniList();
        if (appParmsIniList != null && !appParmsIniList.isEmpty()) {
            appParmsIniList.stream()
                    .filter(
                            pini -> {
                                if (pini.getTrackFromStep() >= stepno
                                        || (pini.getSetToStep() >= stepno
                                                && pini.getSetToStep() != EnvironmentVariables.TOSTEPANY)) {
                                    return true;
                                }
                                return false;
                            })
                    .forEach(
                            pini_filtered -> {
                                hasnolist.add(pini_filtered);
                            });
        }
        return hasnolist;
    }

    public ParmGenMacroTraceParams getParmGenMacroTraceParams(){
        ParmGenMacroTraceParams pmtParams = new ParmGenMacroTraceParams(this.selected_request, this.last_stepno, this.tabIndex);
        return pmtParams;
    }

    /**
     * update AppParmsIni and clear cookie/token caches if newAppParmsIniList == null and
     * getAppParmsIniList() != null then nothing to do(current ParmIniList remains)
     *
     * @param newAppParmsIniList
     */
    public void updateAppParmsIniAndClearCache(List<AppParmsIni> newAppParmsIniList) {
        List<AppParmsIni> appParmsIniList = getAppParmsIniList();
        if (appParmsIniList == null || newAppParmsIniList != null) {
            if (newAppParmsIniList == null) {
                newAppParmsIniList = new ArrayList<>(); // avoid set null to newAppParmsIniList
            }
            setAppParmsIniList(newAppParmsIniList);
        }
    }

    /**
     * set sequence encoding
     *
     * @param encode
     */
    public void setSequenceEncode(Encode encode) {
        this.sequenceEncode = encode;
    }

    /**
     * get sequence encoding
     *
     * @return Encode
     */
    public Encode getSequenceEncode() {
        return sequenceEncode;
    }

    public Encode getLastResponseEncode() {
        if (lastResponseEncode == null) {
            return sequenceEncode;
        }
        return lastResponseEncode;
    }

    public boolean isURIOfRequestIsModified() {
        return isURIOfRequestIsModified;
    }

    public void setURIOfRequestIsModified(boolean b) {
        this.isURIOfRequestIsModified = b;
    }

    public boolean isCacheNull() {
        return this.isCacheNull;
    }

    public void setRunningStepNo(int step) {
        this.runningStepNo = step;
    }

    public int getRunningStepNo() {
        return this.runningStepNo;
    }

    public void restoreOrigialToRequestList() {
        this.rlist = ListDeepCopy.listDeepCopyPRequestResponse(this.originalrlist);
    }




}
