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
package org.zaproxy.zap.extension.automacrobuilder.zap;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.PolicyManager;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceParams;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;

/** @author gdgd009xcd */
public class ExtensionActiveScanWrapper extends ExtensionActiveScan {

    private ScannerParam scannerParam = new ScannerParam();
    private ExtensionActiveScan extension =
            Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.class);
    private StartedActiveScanContainer startedascan = new StartedActiveScanContainer();
    private ParmGenMacroTraceParams targetStepNo = null;

    ExtensionActiveScanWrapper() {}

    protected StartedActiveScanContainer getStartedActiveScanContainer() {
        return this.startedascan;
    }

    protected ExtensionActiveScan getExtensionActiveScan() {
        return this.extension; // Singleton
    }

    @Override
    public ScannerParam getScannerParam() {
        return this.scannerParam; // Singleton
    }

    @Override
    public PolicyManager getPolicyManager() {
        return this.getExtensionActiveScan().getPolicyManager();
    }

    @Override
    public int startScan(Target target, User user, Object[] contextSpecificObjects) {
        for (Object o : contextSpecificObjects) {
            if (o instanceof ScannerParam) {
                ((ScannerParam) o).setHandleAntiCSRFTokens(false);
                break;
            }
        }

        final ParmGenMacroTraceParams tsno = this.targetStepNo;
        this.targetStepNo = null;

        // START scan.
        // below start method can multipre call per targetStepNo.
        return this.startedascan.startScan(
                () -> {
                    int id = this.extension.startScan(target, null, contextSpecificObjects);
                    return this.getScan(id);
                },
                tsno);
    }

    @Override
    public ActiveScan getScan(int id) {
        return this.extension.getScan(id);
    }

    /**
     * Set targetStepNo pass to StartedActiveScan
     *
     * @param targetStepNo
     */
    public void setTargetStepNo(ParmGenMacroTraceParams targetStepNo) {
        this.targetStepNo = targetStepNo;
    }
}
