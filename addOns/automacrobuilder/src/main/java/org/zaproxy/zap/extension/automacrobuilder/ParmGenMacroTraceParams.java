package org.zaproxy.zap.extension.automacrobuilder;

public class ParmGenMacroTraceParams {
    private int tabIndex = -1; // Macro Request List tabindex in MacroBuilderUI
    private int selected_request = -1; // scan target request stepno in ParmGenMacroTrace stepno
    private int last_stepno = -1; // scan last request stepno in ParmGenMacroTrace stepno

    public ParmGenMacroTraceParams(int pos, int lastStepNo, int tabindex) {
        setSelectedRequestNo(pos);
        setLastStepNo(lastStepNo);
        this.tabIndex = tabindex;
    }

    public ParmGenMacroTraceParams(ParmGenMacroTraceParams pmtParams) {
        this.selected_request = pmtParams.selected_request;
        this.last_stepno = pmtParams.last_stepno;
        this.tabIndex = pmtParams.getTabIndex();
    }

    public ParmGenMacroTraceParams(String hv) {
        setString(hv);
    }

    /**
     * Set Scan target request stepno in ParmGenMacroTrace.
     *
     * @param current
     */
    private void setSelectedRequestNo(int current) {
        this.selected_request = current;
    }

    /**
     * Get Scan target request stepno in ParmGenMacroTrace.
     *
     * @return
     */
    public int getSelectedRequestNo() {
        return this.selected_request;
    }

    /**
     * Set last perform request step in ParmGenMacroTrace. if this value == -1 then perform request
     * entire ParmGenMacroTrace.rlist requests.
     *
     * @param last
     */
    private void setLastStepNo(int last) {
        this.last_stepno = last;
    }

    /**
     * Get last perform request step in ParmGenMacroTrace. if this value == -1 then perform request
     * entire ParmGenMacroTrace.rlist requests.
     *
     * @return
     */
    public int getLastStepNo() {
        return this.last_stepno;
    }

    /**
     * get Macro Request List tabIndex in MacroBuilderUI
     *
     * @return
     */
    public int getTabIndex() {
        return this.tabIndex;
    }

    public String toString() {
        return Integer.toString(this.selected_request)
                + "|"
                + Integer.toString(this.last_stepno)
                + "|"
                + Integer.toString(this.tabIndex);
    }

    private void setString(String s) {
        if (s != null) {
            String[] nv = s.split("\\|");
            int nvlen = nv.length;
            String[] nvpair = new String[nvlen];
            while (nvlen-- > 0) {
                nvpair[nvlen] = nv[nvlen];
            }

            selected_request = nv.length > 0 ? Integer.parseInt(nvpair[0]) : -1;
            last_stepno = nv.length > 1 ? Integer.parseInt(nvpair[1]) : -1;
            this.tabIndex = nv.length > 2 ? Integer.parseInt(nvpair[2]) : -1;
        }
    }
}
