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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * ThreadManager
 *
 * @author daike
 */
public class ThreadManager {

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    static final long TEST_DIVIDER = 1; // release: 1 TEST: 10

    static final int MAX_PROCESS =
            8; // Maximum number of concurrent process(sequece of InterfaceDoActions which run in
    // getSequenceNo ascent order)

    static final long MAX_WAIT_TIME =
            30000 / TEST_DIVIDER; // Wait up to 30 seconds between httpsend and receive time

    static final long MAX_GIVE_UP_WAIT_TIME =
            180 * 1000 / TEST_DIVIDER; // whole process wait until 3 minutes

    static final long RECYCLE_INTERVAL_TIME = MAX_WAIT_TIME;

    private long thcount = 0;

    private Map<Long, OneThreadProcessor> pmap = null;

    private Map<String, Long> results = null;

    private List<InterfaceEndAction> actionlist = null;

    // debug params used when LOGGER4J.isDebugEnabled() is true
    private Long debug_endedcount; // total isEnd()  thread count
    private Long debug_totalcount; // total thread counter
    private Long debug_intrcount; // total interrupted thread count
    private Long debug_maxpmapsize; // peek pmap size

    private void d_totalCountUp() {
        synchronized (debug_totalcount) {
            debug_totalcount++;
        }
    }

    private void d_endedCountUp() {
        synchronized (debug_endedcount) {
            debug_endedcount++;
        }
    }

    private void d_intrCountUp() {
        synchronized (debug_intrcount) {
            debug_intrcount++;
        }
    }

    private void d_setMaxPmap(int siz) {
        synchronized (debug_maxpmapsize) {
            if (this.debug_maxpmapsize < siz) {
                this.debug_maxpmapsize = Integer.toUnsignedLong(siz);
            }
        }
    }

    ThreadManager() {
        pmap = new ConcurrentHashMap<>();
        results = new HashMap<>(); // for test use only.
        thcount = 0;
        actionlist = new CopyOnWriteArrayList<>();
        debug_endedcount = new Long(0);
        debug_totalcount = new Long(0);
        debug_intrcount = new Long(0);
        debug_maxpmapsize = new Long(0);
    }

    private String getThreadStatus(Thread.State st) {
        String stval = "";
        switch (st) {
            case NEW:
                stval = "NEW";
                break;
            case RUNNABLE:
                stval = "RUNNABLE";
                break;
            case BLOCKED:
                stval = "BLOCKED";
                break;
            case WAITING:
                stval = "WAITING";
                break;
            case TIMED_WAITING:
                stval = "TIMED_WAITING";
                break;
            case TERMINATED:
                stval = "TERMINATED";
                break;
            default:
                stval = "UNKNOWN";
                break;
        }
        return stval;
    }

    /**
     * Get newly start process instance. instance is create or recycled.
     *
     * @param provider
     * @return
     */
    synchronized OneThreadProcessor getProcess(InterfaceDoActionProvider provider) {

        OneThreadProcessor p = null;
        Thread th = Thread.currentThread();
        long id = th.getId();
        long siz =
                pmap.entrySet().stream()
                        .filter(ent -> ent.getValue().getSequenceNo() == provider.getSequnceNo())
                        .count();
        if (siz < MAX_PROCESS) {
            thcount++;
            p = new OneThreadProcessor(this, th, provider);
            pmap.put(p.getid(), p);
            if (LOGGER4J.isDebugEnabled()) {
                d_totalCountUp();
            }
            if (LOGGER4J.isDebugEnabled()) d_setMaxPmap(pmap.size());
        } else {
            LOGGER4J.debug(
                    "MAX_PROCESS reached. seqno:"
                            + provider.getSequnceNo()
                            + " threadid:"
                            + id
                            + " siz:"
                            + siz
                            + "  this:"
                            + this);
            List<Long> endedp = null;
            long giveuptimer = System.currentTimeMillis();
            LOGGER4J.debug("start RECYCLE LOOP time:" + giveuptimer);
            while (System.currentTimeMillis() - giveuptimer < MAX_GIVE_UP_WAIT_TIME
                    && (endedp == null || endedp.size() <= 0)) {
                endedp =
                        pmap.entrySet().stream()
                                .filter(
                                        ent ->
                                                (ent.getValue().isEnd()
                                                                || ent.getValue().howManyWaitTime()
                                                                        > MAX_WAIT_TIME)
                                                        && ent.getValue().getSequenceNo()
                                                                == provider.getSequnceNo())
                                .map(ent -> ent.getKey())
                                .collect(Collectors.toList());

                if (endedp != null && endedp.size() > 0) break;

                LOGGER4J.debug(
                        "RECYCLE LOOP id:"
                                + id
                                + " lapse:"
                                + (System.currentTimeMillis() - giveuptimer)
                                + " starttime:"
                                + giveuptimer);

                try {
                    LOGGER4J.debug("RECYCLE LOOP WAIT IN id:" + id);
                    wait(RECYCLE_INTERVAL_TIME);
                    // sleep(100);
                    LOGGER4J.debug("RECYCLE LOOP WAIT OUT id:" + id);
                } catch (InterruptedException ex) {
                    LOGGER4J.error("wait intterupt", ex);
                    break;
                }
            }

            Long oldid = new Long(-1);
            if (endedp == null || endedp.size() <= 0) {
                Optional<Long> optval =
                        pmap.entrySet().stream().map(ent -> ent.getKey()).findFirst();
                oldid = optval.get();
                LOGGER4J.warn("MAX_GIVE_UP_WAIT_TIME reached. enforce recycling oldid:" + oldid);
            } else {
                oldid = endedp.get(0);
            }

            try {
                OneThreadProcessor oldp = pmap.get(oldid);
                Thread oldth = oldp.getThread();
                oldp.setInterrupt();

                LOGGER4J.debug(
                        "selected recycle object id:"
                                + oldp.getid()
                                + " status:"
                                + (oldp.isEnd() ? "END" : "RUNNING")
                                + " seqno:"
                                + oldp.getSequenceNo()
                                + " Thread Stat:"
                                + getThreadStatus(oldth.getState())
                                + " WAITTIME:"
                                + oldp.howManyWaitTime()
                                + (oldp.howManyWaitTime() > MAX_WAIT_TIME ? ">" : "<=")
                                + MAX_WAIT_TIME
                                + " isinterrupt:"
                                + (oldth.isInterrupted() ? "YES" : "NO")
                                + " wasInterrupt:"
                                + (oldp.wasInterrupted() ? "YES" : "NO"));

                p = pmap.get(oldid);

                // if(oldp.isEnd()){//  oldp is interrupted but not Ended.
                thcount++;
                // }
            } finally {
            }

            if (LOGGER4J.isDebugEnabled()) {
                d_totalCountUp();
            }

            if (!p.isEnd()) {
                p = new OneThreadProcessor(this, th, provider);
                LOGGER4J.debug(
                        "NEWLY CREATED. seqno:"
                                + p.getSequenceNo()
                                + " old is runnig end id:"
                                + oldid
                                + "->"
                                + id);
            } else {
                p.setNewThread(th, provider);
                LOGGER4J.debug(
                        "RECYCLED. seqno:" + p.getSequenceNo() + " end id:" + oldid + "->" + id);
            }
            pmap.remove(oldid);
            pmap.put(id, p);
            if (LOGGER4J.isDebugEnabled()) d_setMaxPmap(pmap.size());
        }
        return p;
    }

    public boolean beginProcess(InterfaceDoActionProvider provider) {
        OneThreadProcessor p = null;
        try {
            if ((p = getProcess(provider)) != null) {
                p.doProcess(provider.getActionNo());
                if (LOGGER4J.isDebugEnabled()) {
                    d_endedCountUp();
                }
                if (p.wasInterrupted()) {
                    if (LOGGER4J.isDebugEnabled()) {
                        d_intrCountUp();
                    }
                    return false;
                }
                return true;
            } else {
                LOGGER4J.error("id:" + Thread.currentThread().getId() + " BEGIN FAILED p is null");
            }
        } catch (Exception ex) {
            LOGGER4J.error("Exception", ex);
        }
        return false;
    }

    synchronized boolean endProcess(
            OneThreadProcessor p, InterfaceDoAction action, boolean doendaction) {
        OneThreadProcessor endp = null;
        boolean aborted = false;

        try {
            thcount--;
            if (!p.wasInterrupted()
                    && action != null
                    && !p.isAborted()) { // interrupt or abnormal then endaction omit.
                InterfaceEndAction endaction =
                        action.endAction(
                                this, p); // Whether to run endAction or not, always get endaction
                // because if endAction stored ThreadLocal, then must be remove it.
                if (doendaction) {
                    if (endaction != null) {
                        actionlist.add(endaction);
                    } else {
                        LOGGER4J.warn("endaction is null id:" + p.getid());
                    }
                } else {
                    LOGGER4J.warn(
                            "skipped endaction because DoAction return false id:" + p.getid());
                }
            } else {
                aborted = true;
                LOGGER4J.debug(
                        "id:"
                                + p.getid()
                                + " NO ENDACTION REASON:"
                                + (p.wasInterrupted() ? " INTERRUPED." : "")
                                + (p.isAborted() ? " ABORTED." : ""));
            }

            LOGGER4J.debug("thcount:" + thcount);

            if (thcount == 0) {
                LOGGER4J.debug(
                        "endProcess action begin id:"
                                + p.getid()
                                + "action.szie:"
                                + actionlist.size());
                actionlist.forEach(act -> act.action());
                actionlist.clear();
                LOGGER4J.debug("endProcess action end id:" + p.getid());
            }
        } catch (Exception ex) {
            LOGGER4J.error("endProcess failed id:" + p.getid(), ex);
        } finally {

            p.Ended();
            if (!aborted) {
                LOGGER4J.debug(
                        "endProcess OK id:"
                                + p.getid()
                                + " WASINTERRUPED:"
                                + (p.wasInterrupted() ? "YES" : "NO"));
            } else {
                LOGGER4J.warn(
                        "endProcess ABORTED WASINTERRUPTED:"
                                + (p.wasInterrupted() ? "YES" : "NO")
                                + " id:"
                                + p.getid());
            }
            LOGGER4J.debug("endProcess  id:" + p.getid());
            notifyAll();
        }
        return aborted;
    }

    public boolean isStarted(long tid) {
        return pmap.containsKey(tid);
    }

    public OneThreadProcessor getProcessWithId(long thid) {
        Optional<OneThreadProcessor> opt =
                pmap.entrySet().stream()
                        .filter(ent -> ent.getKey() == thid)
                        .map(ent -> ent.getValue())
                        .findFirst();
        OneThreadProcessor proc = opt.orElse(null);
        return proc;
    }

    public void debug_printresults() {

        LOGGER4J.debug("resultsize:" + results.size());

        LOGGER4J.debug("totalthread:" + this.debug_totalcount);
        LOGGER4J.debug("Endedthread:" + this.debug_endedcount);
        LOGGER4J.debug("Failedthread:" + (this.debug_totalcount - this.debug_endedcount));
        LOGGER4J.debug("Interruptedthread:" + this.debug_intrcount);
        LOGGER4J.debug("max pmap size:" + this.debug_maxpmapsize);
    }

    private synchronized void dummyinternalwaiter() {
        try {
            LOGGER4J.info("enter dummyinternalwaiter wait id:" + Thread.currentThread().getId());
            wait(1000);
            LOGGER4J.info("leave dummyinternalwaiter wait id:" + Thread.currentThread().getId());
        } catch (InterruptedException ex) {
            LOGGER4J.error("id:" + Thread.currentThread().getId(), ex);
        }
    }
}
