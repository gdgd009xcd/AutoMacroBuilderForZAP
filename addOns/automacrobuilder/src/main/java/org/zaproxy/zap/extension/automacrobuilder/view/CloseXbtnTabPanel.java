package org.zaproxy.zap.extension.automacrobuilder.view;

import static org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables.ZAP_ICONS;

import java.awt.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;

@SuppressWarnings("serial")
public class CloseXbtnTabPanel extends JPanel {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final ImageIcon CLOSE_BUTTON_ICON =
            MyFontUtils.getScaledIcon(
                    new ImageIcon(MacroBuilderUI.class.getResource(ZAP_ICONS + "/close2.png")));

    JButton closeJButton = new JButton();

    public CloseXbtnTabPanel(String tabTitle, java.awt.event.ActionListener listener) {
        super(new FlowLayout(FlowLayout.CENTER, 0, 0));

        JLabel tabtitleJLabel = new JLabel(tabTitle);
        this.add(tabtitleJLabel);

        closeJButton.setToolTipText(
                EnvironmentVariables.getZapResourceString("autoMacroBuilder.CloseXbtnTabPanel.closeJButtonToolTip.text"));
        closeJButton.setIcon(CLOSE_BUTTON_ICON);
        closeJButton.setBorderPainted(false);
        closeJButton.setBorder(new EmptyBorder(4, 4, 4, 4));
        closeJButton.setFocusable(false);

        this.add(closeJButton);

        setEnableCloseButton(false);

        closeJButton.addActionListener(listener);
    }

    public void setEnableCloseButton(boolean enable) {
        closeJButton.setEnabled(enable);
        closeJButton.setVisible(enable);
    }
}
