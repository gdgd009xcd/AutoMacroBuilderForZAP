package org.zaproxy.zap.extension.automacrobuilder;

public class ParmGenMacroTraceParams {
    public int selected_request = -1; // scan target request stepno in ParmGenMacroTrace stepno
    public int last_stepno = -1; // scan last request stepno in ParmGenMacroTrace stepno

    public ParmGenMacroTraceParams() {}

    /**
     * Set Scan target request stepno in ParmGenMacroTrace.
     *
     * @param current
     */
    public void setSelectedRequestNo(int current) {
        selected_request = current;
    }

    /**
     * Get Scan target request stepno in ParmGenMacroTrace.
     * @return
     */
    public int getSelectedRequestNo() {
        return selected_request;
    }

    /**
     * Set last perform request step in ParmGenMacroTrace.
     * if this value == -1 then perform request entire ParmGenMacroTrace.rlist requests.
     * @param last
     */
    public void setLastStepNo(int last) {
        last_stepno = last;
    }

    /**
     * Get last perform request step in ParmGenMacroTrace.
     * if this value == -1 then perform request entire ParmGenMacroTrace.rlist requests.
     *
     * @return
     */
    public int getLastStepNo() {
        return last_stepno;
    }
    
    public String toString() {
        return Integer.toString(selected_request) + "|" + Integer.toString(last_stepno);
    }
    
    public void setString(String s) {
        if (s != null) {
            String[] nv = s.split("\\|");
            String[] nvpair = new String[2];
            if (nv.length > 0) {
                nvpair[0] = nv[0]; // nv[0] is not null
            } else {
                nvpair[0] = "-1";
            }
            if (nv.length > 1) {
                nvpair[1] = nv[1]; // nv[1] is not null
            } else {
                nvpair[1] = "-1";
            }
            selected_request = Integer.parseInt(nvpair[0]);
            last_stepno = Integer.parseInt(nvpair[1]);
        }
    }
}
