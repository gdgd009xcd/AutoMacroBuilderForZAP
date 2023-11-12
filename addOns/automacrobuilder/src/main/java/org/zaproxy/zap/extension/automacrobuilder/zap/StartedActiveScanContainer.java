/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.parosproxy.paros.core.scanner.Scanner;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.automacrobuilder.ParmGen;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceParams;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceProvider;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;

/**
 * StartedActiveScanContainer
 *
 * @author gdgd009xcd
 */
public class StartedActiveScanContainer {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private MacroBuilderUI mbui;
    private ParmGenMacroTraceProvider pmtProvider = null;
    private Map<ActiveScan, ParmGenMacroTraceParams> traceParamsMapByActiveScan = null;

    // ThreadLocal is actually Map<Thread, anyClass>.
    // if Thread is teminated then automatically remove entry in map.
    //
    private static final ThreadLocal<Long> STARTED_THREADS = new ThreadLocal<>();
    private static final ThreadLocal<UUID> STARTED_UUIDS = new ThreadLocal<>();
    private static final ThreadLocal<ParmGenMacroTraceParams> STARTED_PMTPARAMS =
            new ThreadLocal<>();

    private Map<Integer, String> scanLogPanelScannerIdMap = null;

    private static final ThreadLocal<ParmGenMacroTraceParams> CUSTOMACTIVESCAN_PMTPARAMS = new ThreadLocal<>();




    private Map<Scanner, ParmGenMacroTraceParams> customActiveScanTraceParamsMapByScanner = null;

    StartedActiveScanContainer(ParmGenMacroTraceProvider pmtProvider, MacroBuilderUI mbui) {
        this.pmtProvider = pmtProvider;
        this.traceParamsMapByActiveScan = new ConcurrentHashMap<>();
        this.customActiveScanTraceParamsMapByScanner = new ConcurrentHashMap<>();
        this.scanLogPanelScannerIdMap = new ConcurrentHashMap<>();
        this.mbui = mbui;
    }

    /**
     * Start ActiveScan and add it to list.
     *
     * @param startscan
     * @return int id
     */
    protected int startScan(InterfaceStartScan startscan, ParmGenMacroTraceParams tstep) {
        int id = -1;
        try {
            cleanupStoppedActiveScan();
            ActiveScan ascan = startscan.startScan();
            traceParamsMapByActiveScan.put(ascan, tstep);
            id = ascan.getId();
            LOGGER4J.debug("startScan currentstepno: " + tstep.getSelectedRequestNo());
        } finally {
        }
        return id;
    }

    /**
     * remove Stopped ActiveAcan from ConcurrentMaps.
     *
     * <p>from list
     */
    protected void cleanupStoppedActiveScan() {
        Map<ActiveScan, ParmGenMacroTraceParams> cleanupmap =
                traceParamsMapByActiveScan.entrySet().stream()
                        .filter(ent -> !ent.getKey().isStopped())
                        .collect(Collectors.toMap(ent -> ent.getKey(), ent -> ent.getValue()));

        if (cleanupmap != null && cleanupmap.size() > 0) {
            traceParamsMapByActiveScan = cleanupmap;
            LOGGER4J.debug("cleanup running scans:" + traceParamsMapByActiveScan.size());
        } else {
            traceParamsMapByActiveScan.clear();
            LOGGER4J.debug("clearup all scans");
        }
    }

    /**
     * return true if ascan started from this Extension
     *
     * @param ascan
     * @return boolean
     */
    public boolean isStartedActiveScan(Scanner ascan) {
        boolean result = false;
        try {
            result = traceParamsMapByActiveScan.containsKey(ascan);
        } finally {
        }
        return result;
    }

    /**
     * Set ParmGenMacroTraceParams in beforeScan ScannerHook.
     *
     * @param ascan
     */
    public void addParmGenMacroTraceParams(Scanner ascan) {
        STARTED_PMTPARAMS.set(traceParamsMapByActiveScan.get(ascan));
    }

    /**
     * set ParmGenMacroTraceParams  in PopUpSingleSend or AuthenticationMethodType.
     * @param pmtParams
     */
    public void addParmGenMacroTraceParams(ParmGenMacroTraceParams pmtParams) {
        STARTED_PMTPARAMS.set(pmtParams);
    }

    /**
     * Get ParmGenMacroTrace parameters.
     *
     * @return return value at first call only.
     */
    public ParmGenMacroTraceParams getParmGenMacroTraceParams() {
        try {
            return STARTED_PMTPARAMS.get();
        } finally {
            STARTED_PMTPARAMS.remove();
        }
    }

    /**
     * Add thread id to STARTED_THREADS
     *
     * <p>this method called at ScannerHook's beforeScan
     */
    public void addTheadid() {
        STARTED_THREADS.set(Thread.currentThread().getId());
    }

    /**
     * Remove thread id from STARTED_THREADS
     *
     * <p>this method called in onHttpRequestSend after called isThreadFromStartedActiveScanners
     */
    public void removeThreadid() {
        STARTED_THREADS.remove();
    }

    /**
     * return true if sender started from this Extension. this method called in onHttpRequestSend
     *
     * @param id
     * @return
     */
    public boolean isThreadFromStartedActiveScanners(long id) {
        // return threadidscanhash.containsKey(id);
        Long hooked_id = STARTED_THREADS.get();
        if (hooked_id != null) {
            return true;
        }
        return false;
    }

    /**
     * Set UUID which is generated by ParmGenMacroTraceProvider for currentthread
     *
     * @param uuid
     */
    public void addUUID(UUID uuid) {
        LOGGER4J.debug("addUUID:" + uuid + "currentThread:" + Thread.currentThread().getId());
        STARTED_UUIDS.set(uuid);
    }

    /**
     * Remove UUID which is generated
     *
     * <p>by ParmGenMacroTraceProvider for currentthread
     */
    public void removeUUID() {
        LOGGER4J.debug(
                "removeUUID:" + getUUID() + " currentThread:" + Thread.currentThread().getId());
        STARTED_UUIDS.remove();
    }

    /**
     * Get UUID which is generated by ParmGenMacroTraceProvider for currentthread
     *
     * @return UUID or null
     */
    public UUID getUUID() {
        return STARTED_UUIDS.get();
    }

    /**
     * get Running thread instance of ParmGenMacroTrace
     *
     * @return
     */
    public ParmGenMacroTrace getRunningInstance() {
        UUID uuid = getUUID();
        LOGGER4J.debug("getRunningInstance UUID:" + uuid + "currentThread:" + Thread.currentThread().getId());
        return this.pmtProvider.getRunningInstance(uuid);
    }

    /**
     * update ParmGenMacroTrace of baseInstance with runningInstance.
     *
     * @param runningInstance
     */
    public void updateBaseInstance(ParmGenMacroTrace runningInstance) {
        int tabIndex = runningInstance.getTabIndex();
        LOGGER4J.debug("updateBaseInstance tabIndex:" + tabIndex);
        ParmGenMacroTrace pmtBase = this.pmtProvider.getBaseInstance(tabIndex);
        if (pmtBase != null) {
            pmtBase.updateOriginalBase(runningInstance);
        }
        this.pmtProvider.removeSwingRunner(tabIndex);
    }

    public void removeEndInstance() {
        try {
            UUID uuid = getUUID();
            this.pmtProvider.removeEndInstance(uuid);
        } catch (Exception e) {
            LOGGER4J.error("", e);
        } finally {
            LOGGER4J.debug("removeEndInstance removed UUID[" + getUUID() + "]");
            removeUUID(); // cleanup UUID for this thread.
        }
    }

    public ParmGenMacroTrace getNewRunningInstance(HttpSender sender) {
        ParmGenMacroTraceParams pmtParams = getParmGenMacroTraceParams();
        return this.pmtProvider.getNewParmGenMacroTraceInstance(sender, pmtParams);
    }

    public void addRunningInstance(ParmGenMacroTrace runningInstance) {
        UUID uuid = runningInstance.getUUID();
        addUUID(uuid);
        this.pmtProvider.addRunningInstance(runningInstance);
    }

    public void addCustomActiveScanPmtParamsByScanner(Scanner scanner, ParmGenMacroTraceParams pmtParams){
        LOGGER4J.info("addCustomActiveScanPmtParamsByScanner scanid=" + scanner.getId() + " selectedRequestNo=" + pmtParams.getSelectedRequestNo());
        this.customActiveScanTraceParamsMapByScanner.put(scanner, pmtParams);
    }


    public void clearCustomActiveScanPmtParamsByScanner() {
        this.customActiveScanTraceParamsMapByScanner.clear();
    }

    public boolean hasCustomActiveScanPmtParamsByScanner(int scannerId) {
        List<ParmGenMacroTraceParams> foundList = this.customActiveScanTraceParamsMapByScanner.entrySet().stream()
                .filter(ent -> ent.getKey().getId() == scannerId)
                .map(ent -> ent.getValue())
                .collect(Collectors.toList());
        return !foundList.isEmpty();
    }
    public int sizeOfCustomActiveScanPmtParamsByScanner() {
        return this.customActiveScanTraceParamsMapByScanner.size();
    }

    public void cleanUpCustomActiveScanPmtParamsByScanner(Integer[] postedArray) {
        Map<Scanner, ParmGenMacroTraceParams> cleanupmap =
                this.customActiveScanTraceParamsMapByScanner.entrySet().stream()
                        .filter(ent -> {
                            for (Integer i: postedArray) {
                                if (i==ent.getKey().getId()) {
                                    return true;
                                }
                            }
                            return false;
                        })
                        .collect(Collectors.toMap(ent -> ent.getKey(), ent -> ent.getValue()));
        this.customActiveScanTraceParamsMapByScanner = cleanupmap;
    }

    public List<Integer[]> getCustomActiveScanPmtParamsArray() {
        List<Integer[]> listIntegerArray = new ArrayList<>();
        Map<Scanner, ParmGenMacroTraceParams> removedParamsMapByScanner = new ConcurrentHashMap<>();
        LOGGER4J.debug("traceParamsMapByScanId size= " + this.customActiveScanTraceParamsMapByScanner.size());
        for(Map.Entry<Scanner, ParmGenMacroTraceParams> entry: this.customActiveScanTraceParamsMapByScanner.entrySet()){
            if (entry.getKey().isStop()) {
                Integer[] integerArray = new Integer[]{
                        entry.getKey().getId(),
                        entry.getValue().getSelectedRequestNo(),
                        entry.getValue().getLastStepNo(),
                        entry.getValue().getTabIndex()
                };
                listIntegerArray.add(integerArray);
            } else {
                //removedParamsMapByScanner.put(entry.getKey(), entry.getValue());
            }
        }
        //this.customActiveScanTraceParamsMapByScanner = removedParamsMapByScanner;
        return listIntegerArray;
    }


    protected void setCustomActiveScanPmtParamsOfThread(ParmGenMacroTraceParams pmtParams) {
        LOGGER4J.debug("setCustomActiveScanPmtParamsOfThread at threadid:" + Thread.currentThread().getId());
        CUSTOMACTIVESCAN_PMTPARAMS.set(pmtParams);
    }

    protected ParmGenMacroTraceParams getCustomActiveScanPmtParamsOfThread() {
        LOGGER4J.debug("get(remove)CustomActiveScanPmtParamsOfThread at threadid:" + Thread.currentThread().getId());
        try {
            return CUSTOMACTIVESCAN_PMTPARAMS.get();
        } finally {
            CUSTOMACTIVESCAN_PMTPARAMS.remove();
        }
    }

    public ParmGenMacroTraceProvider getPmtProvider() {
        return this.pmtProvider;
    }

}
