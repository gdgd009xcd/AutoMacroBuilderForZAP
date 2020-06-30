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

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ParmGenMacroTrace Provider for ThreadManager
 *
 * @author daike
 */
public class ParmGenMacroTraceProvider {

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private static ParmGenMacroTrace pmt_originalbase = new ParmGenMacroTrace();
    private static Map<UUID, ParmGenMacroTrace> pmtmap = new ConcurrentHashMap<>();

    /**
     * get original ParmGenMacroTrace base instance for configuration ( for GUI )
     *
     * @return ParmGenMacroTrace baseinstance
     */
    public static ParmGenMacroTrace getOriginalBase() {
        return pmt_originalbase;
    }

    /**
     * get new instance of ParmGenMacroTrace for scan
     *
     * @param sender
     * @return ParmGenMacroTrace
     */
    public static <T> ParmGenMacroTrace getNewParmGenMacroTraceInstance(T sender, ParmGenMacroTraceParams pmtParams) {
        ParmGenMacroTrace newpmt = pmt_originalbase.getScanInstance(sender, pmtParams);
        pmtmap.put(newpmt.getUUID(), newpmt);
        return newpmt;
    }

    public static ParmGenMacroTrace getRunningInstance(UUID uuid) {
        try {
            return pmtmap.get(uuid);
        } catch (Exception e) {
            LOGGER4J.debug("NULL");
        }
        return null;
    }

    public static synchronized void removeEndInstance(UUID uuid) {
        pmtmap.remove(uuid);
    }
}
