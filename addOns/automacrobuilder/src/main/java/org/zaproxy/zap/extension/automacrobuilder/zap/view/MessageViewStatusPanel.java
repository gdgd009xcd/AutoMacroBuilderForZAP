package org.zaproxy.zap.extension.automacrobuilder.zap.view;

import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionActiveScanWrapper;
import java.awt.*;
import static org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionAutoMacroBuilder.A_TAB_ICON;

@SuppressWarnings("serial")
public class MessageViewStatusPanel extends AbstractPanel {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private MacroBuilderUI mbui;

    public MessageViewStatusPanel(ExtensionActiveScanWrapper extscanwrapper,
                                  MacroBuilderUI mbui,
                                  ExtensionHook exthook) {
        setLayout(new BorderLayout());
        this.setName(
                EnvironmentVariables.getZapResourceString("autoMacroBuilder.MessageViewStatusPanel.title.text")); // without calling this method, then NULL pointer exception will be occured.
        this.setIcon(A_TAB_ICON);
        this.mbui = mbui;
        this.add(mbui.getMessageViewPanel());

    }

    public void setTabIndex(int tabIndex) {

    }
}
