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

import static org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables.ZAP_ICONS;

import java.awt.*;
import javax.swing.*;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.view.MyFontUtils;
import org.zaproxy.zap.utils.DisplayUtils;

/** @author gdgd009xcd */
@SuppressWarnings("serial")
public class MyWorkPanel extends AbstractPanel {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final ImageIcon A_TAB_ICON =
            DisplayUtils.getScaledIcon(
                    new ImageIcon(MyWorkPanel.class.getResource(ZAP_ICONS + "/A.png")));

    MyWorkPanel(
            ExtensionActiveScanWrapper extscanwrapper,
            MacroBuilderUI mbui,
            String name,
            ExtensionHook exthook) {
        setLayout(new CardLayout());
        // JScrollPane jScrollPane = new JScrollPane();
        // jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
        // jScrollPane.setHorizontalScrollBarPolicy(
        //        javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        // jScrollPane.setViewportView(new MacroBuilderUI(pmt).getInnerJPanel());
        this.setName(
                name); // without calling this method, then NULL pointer exception will be occured.

        this.setIcon(A_TAB_ICON);
        javax.swing.JButton scanmacrobtn = mbui.getScanMacroButton();
        javax.swing.JPopupMenu requestlistpopupmenu = mbui.getPopupMenuForRequestList();
        javax.swing.JPopupMenu requesteditpopupmenu = mbui.getPopupMenuRequestEdit();

        exthook.addOptionsParamSet(extscanwrapper.getScannerParam());

        BeforeMacroDoActionProvider beforemacroprovider = new BeforeMacroDoActionProvider();
        PostMacroDoActionProvider postmacroprovider = new PostMacroDoActionProvider();

        PopUpItemSingleSend popupitemsingle =
                new PopUpItemSingleSend(
                        mbui,
                        extscanwrapper.getStartedActiveScanContainer(),
                        beforemacroprovider,
                        postmacroprovider);
        requesteditpopupmenu.add(popupitemsingle);

        PopUpItemActiveScan popupitemscan = new PopUpItemActiveScan(mbui, extscanwrapper);
        requesteditpopupmenu.add(popupitemscan);

        requestlistpopupmenu.remove(0); // remove "SendTo" menu that is only used in burp

        popupitemscan = new PopUpItemActiveScan(mbui, extscanwrapper);
        requestlistpopupmenu.add(popupitemscan);

        // create menuitem for each JPopupMenu.
        popupitemsingle =
                new PopUpItemSingleSend(
                        mbui,
                        extscanwrapper.getStartedActiveScanContainer(),
                        beforemacroprovider,
                        postmacroprovider);
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
