package org.zaproxy.zap.extension.automacrobuilder.view;

import java.awt.*;
import javax.swing.*;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceProvider;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.zap.AutoMacroBuilderAuthenticationMethodType;

@SuppressWarnings("serial")
public class RequestListJDialog extends GridBagJDialog {
    AutoMacroBuilderAuthenticationMethodType.AutoMacroBuilderAuthenticationMethodOptionsPanel
            optionPanel;

    JTabbedPane tabbedPane;
    int selectedTabIndex = -1;
    int selectedTargetNo = -1;

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public RequestListJDialog(
            AutoMacroBuilderAuthenticationMethodType
                            .AutoMacroBuilderAuthenticationMethodOptionsPanel
                    optionPanel) {
        super(
                View.getSingleton().getSessionDialog(),
                "Macro Request List",
                ModalityType.DOCUMENT_MODAL);
        this.optionPanel = optionPanel;
        setUpRequestList();
    }

    public void setUpRequestList() {
        MacroBuilderUI mbui = this.optionPanel.getMacroBuilderUI();
        this.selectedTabIndex = this.optionPanel.getTabIndex();
        this.selectedTargetNo = this.optionPanel.getTargetStepNo();
        int tabCount = mbui.getMacroRequestTabCount();

        if (this.selectedTabIndex < 0 || this.selectedTabIndex >= tabCount) {
            this.selectedTabIndex = 0;
        }

        ParmGenMacroTraceProvider pmtProvider = mbui.getParmGenMacroTraceProvider();
        ParmGenMacroTrace pmt = pmtProvider.getBaseInstance(this.selectedTabIndex);
        int requestListSize = pmt.getRequestListSize();
        if (this.selectedTargetNo < 0 || this.selectedTargetNo >= requestListSize) {
            this.selectedTargetNo = pmt.getCurrentRequestPos();
        }
        if (this.selectedTargetNo < 0 || this.selectedTargetNo >= requestListSize) {
            this.selectedTargetNo = 0;
        }

        // remove and recreate all tabs
        this.tabbedPane.removeAll();
        for (int i = 0; i < tabCount; i++) {
            JList<String> sourceJList = mbui.getRequestJListAtTabIndex(i);
            ListModel<String> sourceListModel = sourceJList.getModel();
            String tabTitle = mbui.getMacroRequestTabTitleAt(i);
            JList<String> requestJList = new JList<>(sourceListModel);
            requestJList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            JScrollPane scroll = new JScrollPane(requestJList);
            scroll.setPreferredSize(new Dimension(400, 400));
            scroll.setAutoscrolls(false);
            if (i == this.selectedTabIndex) {
                requestJList.setSelectedIndex(this.selectedTargetNo);
            }
            requestJList.addListSelectionListener(
                    e -> {
                        if (requestJList.getValueIsAdjusting()) return;
                        this.selectedTabIndex = this.tabbedPane.indexOfComponent(scroll);
                        this.selectedTargetNo = requestJList.getSelectedIndex();
                        LOGGER4J.debug("selected tabindex:" + this.selectedTabIndex);
                        LOGGER4J.debug("selected requestlist: " + this.selectedTargetNo);
                    });
            this.tabbedPane.add(scroll, tabTitle);
        }
    }

    private JTabbedPane createRequestListTabbedPaneFromMacroBuilderUI() {
        this.tabbedPane = new JTabbedPane();
        this.tabbedPane.addChangeListener(
                e -> {
                    this.selectedTabIndex = this.tabbedPane.getSelectedIndex();
                    String t = this.tabbedPane.getTitleAt(this.selectedTabIndex);
                    LOGGER4J.debug("Selected No, title: " + this.selectedTabIndex + "," + t);
                });

        this.tabbedPane.setPreferredSize(new Dimension(400, 400));
        return this.tabbedPane;
    }

    @Override
    protected Component createMainPanelContent() {
        return createRequestListTabbedPaneFromMacroBuilderUI();
    }

    @Override
    protected void okBtnActionPerformed() {
        if (this.selectedTabIndex > -1) {
            this.optionPanel.setTabIndex(this.selectedTabIndex);
        }
        if (this.selectedTargetNo > -1) {
            this.optionPanel.setTergetStepNo(this.selectedTargetNo);
        }
        dispose();
    }

    @Override
    protected void cancelBtnActionPerformed() {
        dispose();
    }
}
