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

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/** @author gdgd009xcd */
public class ParmGenTrackKeyPerThread implements DeepClone {

    private Map<UUID, ParmGenTrackingParam> trackjar =
            null; // Integer: unique key(ascend order.) ParmGenTrackingParam: tracking value

    /**
     * for internal use only
     *
     * @param sobj
     */
    private void setup(ParmGenTrackKeyPerThread sobj) {
        this.trackjar = HashMapDeepCopy.hashMapDeepCopyUuidKParmGenTrackingParamV(sobj.trackjar);
    }

    ParmGenTrackKeyPerThread() {
        trackjar = new HashMap<UUID, ParmGenTrackingParam>();
    }

    // create new unique key. tracking value is null.
    ParmGenTrackingParam create(UUID k) {
        ParmGenTrackingParam tkparam = new ParmGenTrackingParam();
        trackjar.put(k, tkparam);
        return tkparam;
    }

    // save tracking value with unique key.
    void put(UUID key, ParmGenTrackingParam tkparam) {
        trackjar.put(key, tkparam);
        // ParmVars.plog.debuglog(0, "TrackJar put key:" + key);
    }

    // get tracking value with unique key.
    ParmGenTrackingParam get(UUID key) {
        // ParmVars.plog.debuglog(0, "TrackJar get key:" + key);
        return trackjar.get(key);
    }

    void remove(UUID key) {
        trackjar.remove(key);
    }

    void clear() {
        if (trackjar != null) {
            trackjar.clear();
        }
    }

    public boolean isCleared() {
        if (trackjar != null){
            return trackjar.isEmpty();
        }
        return true;
    }

    @Override
    public ParmGenTrackKeyPerThread clone() {
        try {
            ParmGenTrackKeyPerThread nobj = (ParmGenTrackKeyPerThread) super.clone();
            nobj.setup(this);
            return nobj;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(ParmGenTrackKeyPerThread.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
