package org.zaproxy.zap.extension.automacrobuilder.zap.view;

import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.view.MyFontUtils;
import org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionActiveScanWrapper;
import org.zaproxy.zap.extension.automacrobuilder.zap.MyWorkPanel;

import javax.swing.*;
import java.awt.*;

import static org.zaproxy.zap.extension.automacrobuilder.ParmVars.ZAP_ICONS;

@SuppressWarnings("serial")
public class MessageVIewStatusPanel extends AbstractPanel {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private static final ImageIcon A_TAB_ICON =
            MyFontUtils.getScaledIcon(
                    new ImageIcon(MyWorkPanel.class.getResource(ZAP_ICONS + "/A.png")));

    public MessageVIewStatusPanel(ExtensionActiveScanWrapper extscanwrapper,
                                  MacroBuilderUI mbui,
                                  String name,
                                  ExtensionHook exthook) {
        setLayout(new BorderLayout());
        this.setName(
                name); // without calling this method, then NULL pointer exception will be occured.
        this.setIcon(A_TAB_ICON);
        this.add(mbui.getMessageViewPanel());

    }
}
