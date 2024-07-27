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
package org.zaproxy.zap.extension.automacrobuilder.zap;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.PolicyManager;
import org.zaproxy.zap.extension.automacrobuilder.CastUtils;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceParams;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceProvider;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.zap.view.CustomVectorInserter;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/** @author gdgd009xcd */
public class ExtensionActiveScanWrapper extends ExtensionActiveScan {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private ParmGenMacroTraceProvider pmtProvider = null;
    private ScannerParam scannerParam = new ScannerParam();
    private ExtensionActiveScan extension =
            Control.getSingleton().getExtensionLoader().getExtension(ExtensionActiveScan.class);
    private StartedActiveScanContainer startedascan = null;
    private ParmGenMacroTraceParams targetStepNo = null;

    ExtensionActiveScanWrapper(ParmGenMacroTraceProvider pmtProvider, MacroBuilderUI mbui) {
        this.pmtProvider = pmtProvider;
        startedascan = new StartedActiveScanContainer(this.pmtProvider, mbui);
    }

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
        ScannerParam optionalScannerParam = null;
        ScannerParam originalScannerParam = null;
        List<Object> resultSpecificObjectList = new ArrayList<>();
        for (Object o : contextSpecificObjects) {
            if (o instanceof ScannerParam) {
                ScannerParam scannerParam = CastUtils.castToType(o);
                if (originalScannerParam == null) {
                    originalScannerParam = scannerParam;
                    originalScannerParam.setHandleAntiCSRFTokens(false);
                    resultSpecificObjectList.add(o);
                } else {
                    optionalScannerParam = scannerParam;
                }
            } else {
                resultSpecificObjectList.add(o);
            }
        }

        if (optionalScannerParam != null) {
            if (optionalScannerParam.getTargetParamsInjectable() == 0) {
                LOGGER4J.debug("disabled all input target except custom vectors");
                originalScannerParam.setTargetParamsInjectable(0);
                originalScannerParam.setTargetParamsEnabledRPC(ScannerParam.RPC_USERDEF);
            } else {
                int enabledRpc = originalScannerParam.getTargetParamsEnabledRPC();
                enabledRpc |= ScannerParam.RPC_USERDEF;
                originalScannerParam.setTargetParamsEnabledRPC(enabledRpc);
            }
        }


        final ParmGenMacroTraceParams tsno = this.targetStepNo;
        this.targetStepNo = null;

        LOGGER4J.debug("Target URL[" + (target!=null?target
                .getStartNode()
                .getHistoryReference()
                .getURI()
                .toString():"") + "]");
        // START scan.
        // below start method can multipre call per targetStepNo.
        return this.startedascan.startScan(
                () -> {
                    int id = this.extension.startScan(target, null, resultSpecificObjectList.toArray());
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

    protected void cleanUpStartedActiveScan() {
        this.startedascan.cleanupStoppedActiveScan();
    }
}
