/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder;

/**
 * LockInstance
 *
 * @author daike
 */
public class LockInstance {

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private boolean locked;
    private long lockerthreadid = -1;

    public LockInstance() {
        locked = false;
        lockerthreadid = -1;
    }

    public synchronized long lock() {
        long tid = Thread.currentThread().getId();
        LOGGER4J.debug("start lock id:" + tid);
        if (this.lockerthreadid == tid) {
            unlock(-1);
        }
        while (locked) {
            try {
                LOGGER4J.debug("wait in:" + tid);
                wait();
                LOGGER4J.debug("wait out:" + tid);
            } catch (InterruptedException ex) {
                LOGGER4J.error("Exception:" + ex.getMessage());
                unlock(-1);
                return -1;
            }
        }
        // At this point locked == false, but because it is synchronized, no other thread can call
        // this method.
        locked = true;
        lockerthreadid = tid;
        // From now, this instance locked. another threads cannot access until unlock.
        return lockerthreadid;
    }

    public synchronized void unlock(long lockerthread) {
        long thisid = Thread.currentThread().getId();
        if (locked) {
            if (lockerthread != this.lockerthreadid) {
                LOGGER4J.error(
                        "unlock warning: "
                                + "lockthread["
                                + lockerthread
                                + "]!="
                                + "lockerid["
                                + this.lockerthreadid
                                + "] thread:"
                                + thisid);
            }
            LOGGER4J.debug("unlock succeeded id:" + this.lockerthreadid + "thread:" + thisid);
            this.lockerthreadid = -1;
            this.locked = false;
            notifyAll();
        } else {
            LOGGER4J.warn("unlock no locked. thread:" + thisid);
        }
    }
}
