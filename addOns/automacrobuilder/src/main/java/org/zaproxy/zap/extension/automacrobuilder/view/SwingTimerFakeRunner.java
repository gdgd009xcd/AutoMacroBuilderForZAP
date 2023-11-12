package org.zaproxy.zap.extension.automacrobuilder.view;

import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.zap.ZapUtil;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import static org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace.PMT_POSTMACRO_NULL;

public class SwingTimerFakeRunner {


    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();



    TimerInfo timerInfo = null;

    public SwingTimerFakeRunner(int tabIndex, MacroBuilderUI mbui, Runnable afterRunner) {
        timerInfo = new TimerInfo();

        this.timerInfo = new TimerInfo();
        this.timerInfo.tabIndex = tabIndex;
        this.timerInfo.mbui = mbui;
        int listModelSize = mbui.getListModelSize(tabIndex);
        this.timerInfo.counter  = listModelSize;
        this.timerInfo.size = listModelSize;
        this.timerInfo.basePmt = EnvironmentVariables.getBaseInstanceOfParmGenMacroTrace(tabIndex);
        this.timerInfo.pmtProvider = EnvironmentVariables.getMacroBuilderUI().getParmGenMacroTraceProvider();
        this.timerInfo.runnable = afterRunner;

        Runnable runnable = new Runnable() {
            final SwingTimerFakeRunner swingTimerFakeRunner = SwingTimerFakeRunner.this;

            @Override
            public void run() {
                swingTimerFakeRunner.timerInfo.timer = new Timer(80, new ActionListener() {

                    TimerInfo timerInfo = swingTimerFakeRunner.timerInfo;


                    @Override
                    public void actionPerformed(ActionEvent e) {
                        Timer thisTimer = timerInfo.timer;

                        LOGGER4J.debug("timer action start count= " + timerInfo.counter);
                        boolean doAction = true;
                        if (timerInfo.currentPmt != null) {
                            int currentStepNo = timerInfo.currentPmt.getStepNo();
                            int state = timerInfo.currentPmt.getState();
                            int timerStepNo = timerInfo.size - timerInfo.counter;
                            if (state != PMT_POSTMACRO_NULL && currentStepNo >= 0  && currentStepNo < timerStepNo) {
                                doAction = false;
                            }
                            LOGGER4J.debug("doaction="
                                    + (doAction?"True":"False")
                                    + " currentStepNo="
                                    + currentStepNo + " timerStepNo=" + timerStepNo);
                        }
                        if (doAction) {
                            if(timerInfo.counter < 0 ){
                                if (timerInfo.done) {
                                    if (timerInfo.runnable != null) {
                                        timerInfo.runnable.run();
                                    }
                                    LOGGER4J.debug("timer stoppped");
                                    thisTimer.stop();
                                }
                            } else if (timerInfo.counter >= 0){
                                LOGGER4J.debug("timer count:" + timerInfo.counter);
                                int countDown = timerInfo.counter;
                                if (countDown == 0) {
                                    countDown = -1;
                                }
                                timerInfo.mbui.updateJlistForRepaint(timerInfo.tabIndex, timerInfo.basePmt, countDown);
                                timerInfo.counter--;
                            }
                        }
                    }
                });
                timerInfo.timer.setRepeats(true);
                timerInfo.timer.setCoalesce(false);
                LOGGER4J.debug("timer started counter=" + swingTimerFakeRunner.timerInfo.counter );
                swingTimerFakeRunner.timerInfo.timer.start();
            }
        };

        // these runnable will be invoked where is within Swing dispatcher.
        // so this runnable will called almost all thread done.
        ZapUtil.SwingInvokeLaterIfNeeded(runnable);

    }




    public void registRunningInstance(ParmGenMacroTrace currentPmt) {
        this.timerInfo.currentPmt = currentPmt;
    }

    public void doneRunningInstance() {
        this.timerInfo.done = true;
    }


}
