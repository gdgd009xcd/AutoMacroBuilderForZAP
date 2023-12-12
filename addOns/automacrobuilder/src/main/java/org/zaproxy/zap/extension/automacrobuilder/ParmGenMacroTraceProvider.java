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

import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.automacrobuilder.view.SwingTimerFakeRunner;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ParmGenMacroTrace Provider for ThreadManager
 *
 * @author gdgd009xcd
 */
public class ParmGenMacroTraceProvider {

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private Map<UUID, ParmGenMacroTrace> pmtmap; // current Running Instance of pmt
    private List<ParmGenMacroTrace> pmtList; // original pmt list
    private Map<Integer, SwingTimerFakeRunner> swingRunnerMap;

    // The following parameters belong to the application scope.
    // so these parameters keep value until ending application.
    private boolean CBInheritFromCache =
            false; // == true then Cookies is updated with cache from begin.
    private boolean CBFinalResponse =
            false; // == true then scan target request's response is updated with last request's
    // response in macro request list.
    private boolean CBResetToOriginal = false; // == true use original requestresponse.
    private boolean CBreplaceCookie = false; // == true then overwrite Cookie
    private boolean CBreplaceTrackingParam = false; // == true then overwrite Tracking Tokens
    private int waittimer = 0; // wait timer (msec)
    private CookieManager cookieManagerInAppScope;//collecting set-Cookie header values except originated from AutoMacroBuilder

    public void setCBInheritFromCache(boolean b) {
        CBInheritFromCache = b;
    }

    public void setCBFinalResponse(boolean b) {
        CBFinalResponse = b;
    }

    public void setCBResetToOriginal(boolean b) {
        CBResetToOriginal = b;
    }

    public void setCBreplaceCookie(boolean b) {
        CBreplaceCookie = b;
    }

    public void setCBreplaceTrackingParam(boolean _b) {
        CBreplaceTrackingParam = _b;
    }
    public void setUseSwingRunner(int tabIndex, SwingTimerFakeRunner runner) {
        if (!this.swingRunnerMap.containsKey(tabIndex)) {// ignore already existed runner
            this.swingRunnerMap.put(tabIndex, runner);
        }
    }

    public void setWaitTimer(String msec) {
        try {
            waittimer = Integer.parseInt(msec); // msec
            if (waittimer <= 0) waittimer = 0;
        } catch (Exception e) {
            waittimer = 0;
        }
    }

    public boolean getCBInheritFromCache() {
        return this.CBInheritFromCache;
    }

    public boolean getCBFinalResponse() {
        return this.CBFinalResponse;
    }

    public boolean getCBResetToOriginal() {
        return this.CBResetToOriginal;
    }

    public boolean getCBreplaceCookie() {
        return this.CBreplaceCookie;
    }

    public boolean getCBreplaceTrackingParam() {
        return this.CBreplaceTrackingParam;
    }

    public int getWaitTimer() {
        return this.waittimer;
    }

    public boolean isBaseLineMode() {
        return !CBreplaceTrackingParam;
    }

    public ParmGenMacroTraceProvider() {
        pmtmap = new ConcurrentHashMap<>();
        ParmGenMacroTrace pmt_originalbase = new ParmGenMacroTrace();
        pmtList = new ArrayList<>();
        pmtList.add(pmt_originalbase);
        swingRunnerMap = new ConcurrentHashMap<>();
        cookieManagerInAppScope = new CookieManager();
    }

    public void clear() {
        pmtmap.clear();
        ParmGenMacroTrace pmt_originalbase = pmtList.get(0);
        pmtList.clear();
        pmt_originalbase.clear();
        pmtList.add(pmt_originalbase);
        swingRunnerMap.clear();
    }

    /**
     * get ParmGenMacroTrace base instance for configuration ( for GUI )
     *
     * @param tabIndex
     * @return ParmGenMacroTrace baseinstance or maybe null.
     */
    public ParmGenMacroTrace getBaseInstance(int tabIndex) {
        try {
            return pmtList.get(tabIndex);
        } catch (IndexOutOfBoundsException e) {

        }
        return null;
    }


    /**
     * add new ParmGenMacroTrace base instance
     *
     * @return added ParmGenMacroTrace
     */
    public ParmGenMacroTrace addNewBaseInstance() {
        ParmGenMacroTrace pmt_originalbase = new ParmGenMacroTrace();
        pmtList.add(pmt_originalbase);
        return pmt_originalbase;
    }

    /**
     * get Iterator of base instances(ParmGenMacroTrace)
     *
     * @return
     */
    public Iterator<ParmGenMacroTrace> getBaseInstanceIterator() {
        return pmtList.iterator();
    }

    /**
     * remove base instance of the specified index
     *
     * @param index
     */
    public void removeBaseInstance(int index) {
        if (index > 0 && index < pmtList.size()) {
            pmtList.remove(index);
        }
    }

    /**
     * get new instance of ParmGenMacroTrace for scan
     *
     * @param sender
     * @return ParmGenMacroTrace
     */
    public <T> ParmGenMacroTrace getNewParmGenMacroTraceInstance(
            T sender, ParmGenMacroTraceParams pmtParams) {
        ParmGenMacroTrace newpmt =
                getBaseInstance(pmtParams.getTabIndex()).createScanRunningInstance(sender, pmtParams, this);
        pmtmap.put(newpmt.getUUID(), newpmt);

        return newpmt;
    }

    public ParmGenMacroTrace getRunningInstance(UUID uuid) {
        try {
            return pmtmap.get(uuid);
        } catch (Exception e) {
            LOGGER4J.debug("NULL");
        }
        return null;
    }

    public void addRunningInstance(ParmGenMacroTrace runningInstancePmt) {
        pmtmap.put(runningInstancePmt.getUUID(), runningInstancePmt);
    }

    public synchronized void removeEndInstance(UUID uuid) {
        try {
            pmtmap.remove(uuid);

        } catch (Exception e) {
            LOGGER4J.error(
                    "removeEndInstance failed by exception:"
                            + e.getMessage()
                            + " thread:"
                            + Thread.currentThread().getId());
        }
    }


    protected SwingTimerFakeRunner getSwingRunner(int tabIndex) {
        LOGGER4J.debug("get swingRunner tabIndex= " + tabIndex);
        return this.swingRunnerMap.get(tabIndex);// this return previous data or maybe null.
    }

    public void removeSwingRunner(int tabIndex) {
        LOGGER4J.debug("removed swingRunner tabIndex= " + tabIndex);
        SwingTimerFakeRunner runner = this.swingRunnerMap.remove(tabIndex);
        if (runner != null) {
            runner.doneRunningInstance();
        }
    }

    public void parseSetCookie(HttpMessage httpMessage) {
        HttpResponseHeader responseHeader = httpMessage.getResponseHeader();
        // responseHeader.getCookieParams returns header of "set-cookie" and "set-cookie2"
        TreeSet<HtmlParameter> cookies = responseHeader.getCookieParams();
        for(HtmlParameter cookie: cookies) {
            // Set-Cookie: PHPSESSID=875cfa8439d7912bfda16b35e5cfa7df; path=/; expires=Fri, 08-Dec-23 16:51:00 GMT;domain=localhost; HttpOnly; Secure;
            // cookieName = "PHPSESSID";
            // cookieValue = "875cfa8439d7912bfda16b35e5cfa7df";
            // cookieAttrs  = new HashSet<String>(); stored entire [name=value] string like following.
            // cookieAttrs.add("path=/");
            // cookieAttrs.add("expires=Fri, 08-Dec-23 16:51:00 GMT");
            // cookieAttrs.add("domain=localhost");
            // cookieAttrs.add("HttpOnly");
            // cookieAttrs.add("Secure");

            String cookieName = cookie.getName();
            String cookieValue = cookie.getValue();
            Set<String> cookieAttrs = cookie.getFlags();
            StringBuffer setCookieLine = new StringBuffer();
            setCookieLine.append("Set-Cookie: ");
            setCookieLine.append(cookieName + "=" + cookieValue + ";");
            for(String cookieAttr: cookieAttrs) {
                setCookieLine.append(" " + cookieAttr + ";");
            }
            HttpRequestHeader requestHeader = httpMessage.getRequestHeader();
            URI uri = requestHeader.getURI();
            try {
                String hostName = uri.getHost();
                String path = uri.getPath();
                LOGGER4J.debug("domain[" + hostName + "] path[" + path + "] line[" + setCookieLine.toString() + "]");
                this.cookieManagerInAppScope.parse(hostName, path, setCookieLine.toString());
            }catch (Exception ex) {

            }
        }
    }

    public CookieManager getCookieManagerInAppScope() {
        return this.cookieManagerInAppScope;
    }
}
