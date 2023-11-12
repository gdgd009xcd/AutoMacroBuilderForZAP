package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.automacrobuilder.InterfaceAction;
import org.zaproxy.zap.extension.automacrobuilder.InterfaceDoAction;
import org.zaproxy.zap.extension.automacrobuilder.InterfaceEndAction;
import org.zaproxy.zap.extension.automacrobuilder.OneThreadProcessor;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.ThreadManager;

public class PostMacroDoAction implements InterfaceDoAction {
    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private ThreadLocal<List<InterfaceAction>> ACTION_LIST = new ThreadLocal<>();
    private ThreadLocal<InterfaceEndAction> ENDACTION = new ThreadLocal<>();

    PostMacroDoAction() {}

    /**
     * set parameters to InterfaceAction and InterfaceEndAction.
     *
     * @param acon
     * @param msg
     * @param initiator
     * @param sender
     */
    void setParameters(
            StartedActiveScanContainer acon, HttpMessage msg, int initiator, HttpSender sender) {
        final ParmGenMacroTrace pmt = acon.getRunningInstance();
        // set current pmtParam for CustomActiveScan
        acon.setCustomActiveScanPmtParamsOfThread(pmt.getParmGenMacroTraceParams());
        List<InterfaceAction> actionlist = new ArrayList<>();

        // action create and save into ThreadLocal
        actionlist.add(
                (tm1, otp1) -> {
                    ParmGenMacroTrace.clientrequest.postZapCurrentResponse(pmt, msg);
                    pmt.startPostMacro(otp1);
                    ParmGenMacroTrace.clientrequest.updateCurrentResponseWithFinalResponse(
                            pmt, msg);
                    return true;
                });
        ACTION_LIST.set(actionlist);

        // end action create and save into ThreadLocal
        ENDACTION.set(
                () -> {
                    acon.updateBaseInstance(pmt);
                    acon.removeEndInstance();
                });
    }

    @Override
    public List<InterfaceAction> startAction(ThreadManager tm, OneThreadProcessor otp) {
        try {
            List<InterfaceAction> actionlist = ACTION_LIST.get();
            return actionlist;
        } catch (Exception e) {
            LOGGER4J.error("", e);
            return null;
        } finally {
            ACTION_LIST.remove();
        }
    }

    @Override
    public InterfaceEndAction endAction(ThreadManager tm, OneThreadProcessor otp) {
        try {
            // get endaction from ThreadLocal
            InterfaceEndAction endaction = ENDACTION.get();
            return endaction;
        } catch (Exception e) {
            LOGGER4J.error("", e);
            return null;
        } finally {
            ENDACTION.remove();
        }
    }
}
