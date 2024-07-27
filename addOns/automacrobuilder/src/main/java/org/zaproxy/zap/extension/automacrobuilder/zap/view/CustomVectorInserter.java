package org.zaproxy.zap.extension.automacrobuilder.zap.view;

import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.core.scanner.VariantUserDefined;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.extension.ascan.CustomScanDialog;
import org.zaproxy.zap.extension.ascan.CustomScanPanel;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables;
import org.zaproxy.zap.extension.automacrobuilder.zap.CustomTagConverter;
import org.zaproxy.zap.extension.automacrobuilder.zap.DecoderTag;
import org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionActiveScanWrapper;
import org.zaproxy.zap.model.Target;

import javax.swing.*;
import javax.swing.event.CaretEvent;
import javax.swing.event.CaretListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@SuppressWarnings("serial")
public class CustomVectorInserter extends AbstractParamPanel implements CustomScanPanel {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private GridBagLayout gridBagLayout;
    private JTextArea requestPane;
    private JCheckBox disableNonCustomVector;
    private JButton addVectorButton;
    private JButton delVectorButton;
    private final DefaultListModel<Highlighter.Highlight> injectionPointModel = new DefaultListModel<>();
    private Target target = null;
    private CustomScanDialog customScanDialog = null;
    private ExtensionActiveScanWrapper extensionActiveScanWrapper = null;
    private int headerLength = -1;
    // The index of the start of the URL path e.g. after https://www.example.com:1234/ - no point
    // attacking this
    private int urlPathStart = -1;
    public CustomVectorInserter(Target target, ExtensionActiveScanWrapper extension) {
        super();
        gridBagLayout = new GridBagLayout();
        this.setLayout(gridBagLayout);
        this.extensionActiveScanWrapper =  extension;
        this.target = target;
        initialize(target);
    }

    public void updateInit(Target target) {
        this.headerLength = -1;
        this.urlPathStart = -1;
        injectionPointModel.clear();
        populateRequestField(target.getStartNode());
    }

    private void initialize(Target target) {

        this.headerLength = -1;
        this.urlPathStart = -1;
        // JTextArea's setText method use Document.insertString.
        // so CRLF is inserted as is.
        // if you use JTextPane, setText method use Editorkit.
        // so CRLF is converted to LF
        // so I decided to use JTextArea in here.
        requestPane = new JTextArea();

        requestPane.setEditable(true);
        requestPane.setLineWrap(false);
        populateRequestField(target.getStartNode());
        JList<Highlighter.Highlight> insertedVectorList = new JList<>(injectionPointModel);
        insertedVectorList.
                setCellRenderer(
                        new ListCellRenderer<Highlighter.Highlight>() {
                            @Override
                            public Component getListCellRendererComponent(
                                    JList<? extends Highlighter.Highlight> list,
                                    Highlighter.Highlight hlt,
                                    int index,
                                    boolean isSelected,
                                    boolean cellHasFocus) {

                                String str = "";
                                try {
                                    str =
                                            requestPane
                                                    .getText(
                                                            hlt.getStartOffset(),
                                                            hlt.getEndOffset() - hlt.getStartOffset());
                                    if (str.length() > 8) {
                                        // just show first 8 chrs (arbitrary limit;)
                                        str = str.substring(0, 8) + "..";
                                    }
                                } catch (BadLocationException e) {
                                    // Ignore
                                }

                                return new JLabel(
                                        "["
                                                + hlt.getStartOffset()
                                                + ","
                                                + hlt.getEndOffset()
                                                + "]: "
                                                + str);
                            }
                        });
        JScrollPane requestScroller = new JScrollPane();
        requestScroller.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        requestScroller.setViewportView(requestPane);
        BoxAndScrollerPanel boxAndScrollerPanel = new BoxAndScrollerPanel(
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        boxAndScrollerPanel.setComponentToScroller(insertedVectorList);
        addVectorButton =  new JButton("Add");
        addVectorButton.addActionListener(
                new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        // Add the selected injection point
                        int userDefStart = requestPane.getSelectionStart();
                        if (userDefStart >= 0) {
                            int userDefEnd = requestPane.getSelectionEnd();
                            Highlighter hl = requestPane.getHighlighter();
                            Highlighter.HighlightPainter painter =
                                    new DefaultHighlighter.DefaultHighlightPainter(Color.RED);
                            try {
                                Highlighter.Highlight hlt =
                                        (Highlighter.Highlight)
                                                hl.addHighlight(
                                                        userDefStart, userDefEnd, painter);
                                injectionPointModel.addElement(hlt);
                                // Unselect the text
                                requestPane.setSelectionStart(userDefEnd);
                                requestPane.setSelectionEnd(userDefEnd);
                                requestPane.getCaret().setVisible(true);

                            } catch (BadLocationException e1) {

                            }
                        }
                    }
                });
        delVectorButton = new JButton("Del");
        delVectorButton.addActionListener(
                new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        // Remove any selected injection points
                        int userDefStart = requestPane.getSelectionStart();
                        if (userDefStart >= 0) {
                            int userDefEnd = requestPane.getSelectionEnd();
                            Highlighter hltr = requestPane.getHighlighter();
                            Highlighter.Highlight[] hls = hltr.getHighlights();

                            if (hls != null && hls.length > 0) {
                                for (Highlighter.Highlight hl : hls) {
                                    if (selectionIncludesHighlight(
                                            userDefStart, userDefEnd, hl)) {
                                        hltr.removeHighlight(hl);
                                        injectionPointModel.removeElement(hl);
                                    }
                                }
                            }

                            // Unselect the text
                            requestPane.setSelectionStart(userDefEnd);
                            requestPane.setSelectionEnd(userDefEnd);
                            requestPane.getCaret().setVisible(true);
                        }
                    }
                });
        JLabel vectorListTitle = new JLabel("Vectors:");
        boxAndScrollerPanel.addComponentToBoxPanelAtYaxis(addVectorButton);
        boxAndScrollerPanel.addComponentToBoxPanelAtYaxis(delVectorButton);
        boxAndScrollerPanel.addComponentToBoxPanelAtYaxis(vectorListTitle);
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestScroller, boxAndScrollerPanel);
        splitPane.setDividerLocation(550);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        gbc.gridheight = 4;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 0.1d;
        gbc.weighty = 0.1d;
        gbc.insets = new Insets(5, 5, 5, 5);
        // gbc.anchor = GridBagConstraints.CENTER; // this is default.
        gridBagLayout.setConstraints(splitPane, gbc);
        this.add(splitPane);

        JLabel infoLabel = new JLabel(EnvironmentVariables.getZapResourceString("autoMacroBuilder.CustomVectorInserter.infoLabel.title.text"));
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0d;
        gbc.weighty = 0d;
        gbc.insets = new Insets(1, 1, 1, 1);
        gbc.anchor = GridBagConstraints.LINE_START;
        gridBagLayout.setConstraints(infoLabel, gbc);
        this.add(infoLabel);

        disableNonCustomVector = new JCheckBox(EnvironmentVariables.getZapResourceString("autoMacroBuilder.CustomVectorInserter.nonCustom.title.text"));
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0d;
        gbc.weighty = 0d;
        gbc.insets = new Insets(1, 1, 1, 1);
        gbc.anchor = GridBagConstraints.LINE_START;
        gridBagLayout.setConstraints(disableNonCustomVector, gbc);
        this.add(disableNonCustomVector);
        disableNonCustomVector.setSelected(true);
        disableNonCustomVector.setEnabled(true);
        disableNonCustomVector.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });

        // must add this caretLister after being added VectorButtons.
        requestPane.addCaretListener(new CaretListener() {
            @Override
            public void caretUpdate(CaretEvent e) {
                manageAddDelVectorButtons();
            }
        });
    }

    private void populateRequestField(SiteNode node) {
        try {
            if (node == null
                    || node.getHistoryReference() == null
                    || node.getHistoryReference().getHttpMessage() == null) {
                this.requestPane.setText("");

            } else {
                // Populate the custom vectors http pane
                HttpMessage msg = node.getHistoryReference().getHttpMessage();
                String header = msg.getRequestHeader().toString();
                StringBuilder sb = new StringBuilder();
                sb.append(header);

                this.headerLength = header.length();
                this.urlPathStart =
                        header.indexOf("/", header.indexOf("://") + 2)
                                + 1; // Ignore <METHOD> http(s)://host:port/

                sb.append(msg.getRequestBody().toString());
                String decodedRequestText = CustomTagConverter.customDecode(sb.toString());
                this.requestPane.setText(decodedRequestText);


            }

        } catch (HttpMalformedHeaderException | DatabaseException e) {
            //
            this.requestPane.setText("");
        }
        this.requestPane.setCaretPosition(0);
    }

    @Override
    public void initParam(Object obj) {

    }

    @Override
    public void saveParam(Object obj) throws Exception {

    }


    private boolean selectionIncludesHighlight(int start, int end, Highlighter.Highlight hl) {
        if (hl.getPainter() instanceof DefaultHighlighter.DefaultHighlightPainter) {
            DefaultHighlighter.DefaultHighlightPainter ptr =
                    (DefaultHighlighter.DefaultHighlightPainter) hl.getPainter();
            if (ptr.getColor() != null && ptr.getColor().equals(Color.RED)) {
                // Test for 'RED' needed to prevent matching the users selection
                return start < hl.getEndOffset() && end > hl.getStartOffset();
            }
        }
        return false;
    }


    @Override
    public String getLabel() {
        return "autoMacroBuilder.CustomVectorInserter.label.tabname.text";
    }

    @Override
    public AbstractParamPanel getPanel(boolean init) {
        return this;
    }

    @Override
    public Target getTarget() {
        return null;
    }

    /**
     * return errormessage which displays founded errors when starting to scan.
     * @return null - no errors<BR> String - founded error message
     */
    @Override
    public String validateFields() {
        return null;
    }

    public void setCustomScanDialog(CustomScanDialog customScanDialog) {
        this.customScanDialog = customScanDialog;
    }

    @Override
    public Object[] getContextSpecificObjects() {
        List<Object> contextSpecificObjects = new ArrayList<>();
        // save insertion vector
        if (injectionPointModel.getSize() > 0) {
            int[][] injPoints = new int[injectionPointModel.getSize()][];
            Map<Integer, Integer> encodeMap = new HashMap<>();
            for (int i = 0; i < injectionPointModel.getSize(); i++) {

                Highlighter.Highlight hl = injectionPointModel.elementAt(i);
                encodeMap.put(hl.getStartOffset(), -1);
                encodeMap.put(hl.getEndOffset(), -1);
                LOGGER4J.debug("customVector:" + hl.getStartOffset() + "," + hl.getEndOffset());
            }
            DecoderTag.encodeCustomTagWithEncodeMap(this.requestPane.getText(), encodeMap);
            for (int i = 0; i < injectionPointModel.getSize(); i++) {

                Highlighter.Highlight hl = injectionPointModel.elementAt(i);
                injPoints[i] = new int[2];
                injPoints[i][0] = encodeMap.get(hl.getStartOffset());
                injPoints[i][1] = encodeMap.get(hl.getEndOffset());

                LOGGER4J.debug("customVector encoded:" + injPoints[i][0] + "," + injPoints[i][1]);
            }

            try {
                if (target != null && target.getStartNode() != null) {
                    VariantUserDefined.setInjectionPoints(
                            this.target
                                    .getStartNode()
                                    .getHistoryReference()
                                    .getURI()
                                    .toString(),
                            injPoints);

                    ScannerParam scannerParam = enableVariantUserDefinedInScannerParam();
                    contextSpecificObjects.add(scannerParam);

                }

            } catch (Exception e) {
                LOGGER4J.error(e.getMessage(), e);
            }
        }



        return contextSpecificObjects.toArray();
    }

    private ScannerParam enableVariantUserDefinedInScannerParam() {
        ScannerParam scannerParam = extensionActiveScanWrapper.getScannerParam();
        if (disableNonCustomVector.isSelected()) {
            scannerParam.setTargetParamsInjectable(0);
            scannerParam.setTargetParamsEnabledRPC(0);
        }
        int enabledRpc = scannerParam.getTargetParamsEnabledRPC();
        enabledRpc |= ScannerParam.RPC_USERDEF;
        scannerParam.setTargetParamsEnabledRPC(enabledRpc);
        return scannerParam;
    }

    private void manageAddDelVectorButtons() {
        int userDefStart = this.requestPane.getSelectionStart();
        int userDefEnd = this.requestPane.getSelectionEnd();
        if (userDefStart >= 0) {
            if (userDefStart < urlPathStart) {
                // No point attacking the method, hostname or port
                addVectorButton.setEnabled(false);

            } else if (userDefStart < headerLength && userDefEnd > headerLength) {
                // The users selection cross the header / body boundary - thats never going to
                // work well
                addVectorButton.setEnabled(false);

            } else {
                addVectorButton.setEnabled(true);
            }
        }
    }
}
