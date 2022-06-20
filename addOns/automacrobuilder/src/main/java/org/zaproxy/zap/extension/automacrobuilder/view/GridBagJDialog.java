package org.zaproxy.zap.extension.automacrobuilder.view;

import java.awt.*;
import javax.swing.*;

@SuppressWarnings("serial")
public abstract class GridBagJDialog extends JDialog {

    /**
     * create basic dialog<br>
     *
     * <pre>
     *  |------------------------------------------------|
     *  |                                                |
     *  |              mainPanelContent                  |
     *  |                                                |
     *  | -----------------------------------------------|
     *  | | OK |                              |  CANCEL ||
     *  |________________________________________________|
     * </pre>
     */
    public GridBagJDialog(Window owner, String title, ModalityType modalityType) {
        super(owner, title, modalityType);
        init();
    }

    /**
     * create this dialog contents<br>
     * you must implement createMainPanelContent method
     */
    private void init() {
        Component mainPanelContent = createMainPanelContent();
        GridBagLayout layout = new GridBagLayout();
        JPanel panel = new JPanel();
        panel.setLayout(layout);

        GridBagConstraints gbc = new GridBagConstraints();

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());
        mainPanel.add(mainPanelContent, BorderLayout.CENTER);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 4;
        gbc.gridheight = 2;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0d;
        gbc.weighty = 0.8d;
        gbc.insets = new Insets(5, 5, 5, 5);
        layout.setConstraints(mainPanel, gbc);
        panel.add(mainPanel);

        JSeparator separator = new JSeparator();

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 4;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0d;
        gbc.weighty = 0.1d;
        gbc.insets = new Insets(0, 5, 0, 5);
        layout.setConstraints(separator, gbc);
        panel.add(separator);

        JButton okBtn = new JButton("OK");

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.25d;
        gbc.weighty = 0.1d;
        gbc.insets = new Insets(5, 5, 5, 5);
        layout.setConstraints(okBtn, gbc);
        panel.add(okBtn);

        okBtn.addActionListener(
                e -> {
                    okBtnActionPerformed();
                });

        JButton cancelBtn = new JButton("CANCEL");

        gbc.gridx = 3;
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.25d;
        gbc.weighty = 0.1d;
        gbc.insets = new Insets(5, 5, 5, 5);
        layout.setConstraints(cancelBtn, gbc);
        panel.add(cancelBtn);

        cancelBtn.addActionListener(
                e -> {
                    cancelBtnActionPerformed();
                });

        getContentPane().add(panel, "Center");
        setResizable(true);
        pack();
        // set dialog position to centre of Owner window.
        setLocationRelativeTo(getOwner());
    }

    /**
     * implement mainPanelContent component<br>
     *
     * @return Component
     */
    protected abstract Component createMainPanelContent();

    /**
     * OK button Action<br>
     * You must specify dispose() method at last line of this method.
     */
    protected abstract void okBtnActionPerformed();

    /**
     * CANCEL button Action<br>
     * You must specify dispose() method at last line of this method.
     */
    protected abstract void cancelBtnActionPerformed();
}
