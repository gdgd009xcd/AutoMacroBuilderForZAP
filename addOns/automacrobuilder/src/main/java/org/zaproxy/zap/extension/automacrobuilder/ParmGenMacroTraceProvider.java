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
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ParmGenMacroTrace Provider for ThreadManager
 *
 * @author gdgd009xcd
 */
public class ParmGenMacroTraceProvider {

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private Map<UUID, ParmGenMacroTrace> pmtmap;
    private List<ParmGenMacroTrace> pmtList;

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
    }

    public void clear() {
        pmtmap.clear();
        ParmGenMacroTrace pmt_originalbase = pmtList.get(0);
        pmtList.clear();
        pmt_originalbase.clear();
        pmtList.add(pmt_originalbase);
    }

    /**
     * get ParmGenMacroTrace base instance for configuration ( for GUI )
     *
     * @param tabindex
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
     * get new instance of ParmGenMacroTrace for scan
     *
     * @param sender
     * @return ParmGenMacroTrace
     */
    public <T> ParmGenMacroTrace getNewParmGenMacroTraceInstance(
            T sender, ParmGenMacroTraceParams pmtParams) {
        ParmGenMacroTrace newpmt =
                getBaseInstance(pmtParams.getTabIndex()).getScanInstance(sender, pmtParams, this);
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

    public synchronized void removeEndInstance(UUID uuid) {
        pmtmap.remove(uuid);
    }
}
