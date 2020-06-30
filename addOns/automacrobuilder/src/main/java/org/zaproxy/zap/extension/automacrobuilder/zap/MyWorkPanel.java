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

import java.awt.*;

import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.tab.Tab;

/** @author daike */
@SuppressWarnings("serial")
public class MyWorkPanel extends AbstractPanel implements Tab {

    private ParmGenMacroTrace pmt = null;
    private static final org.apache.logging.log4j.Logger LOGGER4J = org.apache.logging.log4j.LogManager.getLogger();

    MyWorkPanel(
            ExtensionActiveScanWrapper extscanwrapper,
            MacroBuilderUI mbui,
            ParmGenMacroTrace pmt,
            String name,
            ExtensionHook exthook) {
        setLayout(new CardLayout());
        // JScrollPane jScrollPane = new JScrollPane();
        // jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
        // jScrollPane.setHorizontalScrollBarPolicy(
        //        javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        this.pmt = pmt;
        // jScrollPane.setViewportView(new MacroBuilderUI(pmt).getInnerJPanel());
        this.setName(
                name); // without calling this method, then NULL pointer exception will be occured.

        javax.swing.JButton scanmacrobtn = mbui.getScanMacroButton();
        javax.swing.JPopupMenu requestlistpopupmenu = mbui.getPopupMenuForRequestList();

        exthook.addOptionsParamSet(extscanwrapper.getScannerParam());

        PopUpItemActiveScan popupitemscan =
                new PopUpItemActiveScan(mbui, extscanwrapper);

        PopUpItemSingleSend popupitemsingle = new PopUpItemSingleSend(mbui, extscanwrapper.getStartedActiveScanContainer());

        requestlistpopupmenu.remove(0); // remove "SendTo" menu that is only used in burp

        requestlistpopupmenu.add(popupitemscan);
        requestlistpopupmenu.add(popupitemsingle);



        // scanmacrobtn.setEnabled(true);
        scanmacrobtn.addActionListener(
                ev -> {
                    System.out.println("Executed event:" + ev.toString());
                });
        this.add(mbui);

        if (LOGGER4J != null) {
            LOGGER4J.debug("new MyWorkPanel");
        }
    }
}
