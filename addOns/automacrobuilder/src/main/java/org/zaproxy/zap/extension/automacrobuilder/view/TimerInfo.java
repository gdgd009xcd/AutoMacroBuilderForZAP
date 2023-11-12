package org.zaproxy.zap.extension.automacrobuilder.view;

import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceProvider;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;

import javax.swing.*;

public class TimerInfo {
    int tabIndex = -1;
    MacroBuilderUI mbui = null;
    ParmGenMacroTraceProvider pmtProvider = null;
    ParmGenMacroTrace basePmt = null;
    ParmGenMacroTrace currentPmt = null;
    int counter = -1;
    Timer timer = null;
    int size = -1;
    Runnable runnable = null;

    boolean done = false;
    public TimerInfo() {

    }
}
