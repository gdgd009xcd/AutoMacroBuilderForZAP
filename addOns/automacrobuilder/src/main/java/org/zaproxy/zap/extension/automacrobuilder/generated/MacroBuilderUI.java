/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.text.JTextComponent;
import javax.swing.text.StyledDocument;
import com.google.gson.JsonElement;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.view.CloseXbtnTabPanel;
import org.zaproxy.zap.extension.automacrobuilder.view.MyFontUtils;
import org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionAutoMacroBuilder;

import static org.zaproxy.zap.extension.automacrobuilder.ParmVars.JSONFileIANACharsetName;
import static org.zaproxy.zap.extension.automacrobuilder.ParmVars.ZAP_ICONS;

/**
 *
 * @author gdgd009xcd
 */
@SuppressWarnings("serial")
public class MacroBuilderUI  extends javax.swing.JPanel implements  InterfaceParmGenRegexSaveCancelAction {

    
    private static org.apache.logging.log4j.Logger logger4j = org.apache.logging.log4j.LogManager.getLogger();
    
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    private static final ImageIcon PLUS_BUTTON_ICON = MyFontUtils.getScaledIcon(
            new ImageIcon(MacroBuilderUI.class.getResource(ZAP_ICONS + "/plus.png")));
    private static final ImageIcon QUESTION_BUTTON_ICON = MyFontUtils.getScaledIcon(
            new ImageIcon(MacroBuilderUI.class.getResource(ZAP_ICONS + "/question.png")));

    // List<PRequestResponse> rlist = null;
    // ParmGenMacroTrace pmt = null;
    
    ParmGenMacroTraceProvider pmtProvider = null;
    List<JList<String>> requestJLists = null;
    DisplayInfoOfRequestListTab displayInfo = null;
    int MacroRequestListTabsCurrentIndex = 0;
    int maxTabIndex = 0;// maximum index number of added tab to RequestList tab

    int EditTarget = -1;
    Encode EditPageEnc = Encode.ISO_8859_1;
    static final int REQUEST_DISPMAXSIZ = 500000;//1MB
    static final int RESPONSE_DISPMAXSIZ = 1000000;//1MB

    JPanel plusBtnPanel = null;


    ExtensionAutoMacroBuilder extensionAutoMacroBuilder = null;

    /**
     * Creates new form MacroBuilderUI
     */
    @SuppressWarnings("unchecked")
    public MacroBuilderUI(ParmGenMacroTraceProvider pmtProvider, ExtensionAutoMacroBuilder extensionAutoMacroBuilder) {
        this.extensionAutoMacroBuilder = extensionAutoMacroBuilder;
        maxTabIndex = 0;
        this.MacroRequestListTabsCurrentIndex = 0;
        this.pmtProvider = pmtProvider;
        ParmGenMacroTrace pmt = this.pmtProvider.getBaseInstance(maxTabIndex);
        displayInfo = new DisplayInfoOfRequestListTab();
        requestJLists = new ArrayList<>();
        initComponents();
        jButton1.setIcon(QUESTION_BUTTON_ICON);
        MacroComments.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                MacroCommentsMousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                MacroCommentsMouseReleased(evt);
            }
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                MacroCommentsMouseClicked(evt);
            }
        });
        jLabel3.putClientProperty("html.disable", Boolean.FALSE);
        logger4j.debug("MacroBuilderUI after initComponents");
        RequestList.setCellRenderer((ListCellRenderer<Object>)new MacroBuilderUIRequestListRender(pmt));
        DefaultListModel<String> RequestListModel = new DefaultListModel<>();
        RequestListModel.clear();
        RequestList.setModel(RequestListModel);

        requestJLists.add(RequestList);

        // Button for adding new Tab to JtabbedPane.
        addPlusTabButtonToRequestList();

        pmt.setUI(this);

        pmtProvider.setCBreplaceCookie(true);
        pmtProvider.setCBInheritFromCache(CBinheritFromCache.isSelected());
        pmtProvider.setCBFinalResponse(FinalResponse.isSelected());
        pmtProvider.setCBResetToOriginal(true);

        pmtProvider.setCBreplaceTrackingParam(isReplaceMode());

        // waittimer setting.
        jCheckBox2ActionPerformed(null);

    }

    public javax.swing.JPopupMenu getPopupMenuForRequestList(){
        return PopupMenuForRequestList;
    }

    public javax.swing.JPopupMenu getPopupMenuRequestEdit() {
        return RequestEdit;
    }

    public javax.swing.JButton getScanMacroButton(){
        return StartScan;
    }

    boolean isReplaceMode(){
        boolean mode = true;
        String selected = (String)TrackMode.getSelectedItem();
        if(selected!=null){
            if(selected.equals("replace")){
                return true;
            }else{
                return false;
            }
        }
        return true;
        
    }

    /**
     * get ParmGenMacroTrace of selected tab<br>
     * <br>
     * Caution: This function may return null<br>
     * if there are no tabs selected in the macro request list.
     *
     * @return ParmGenMacroTrace or maybe null
     */
    public ParmGenMacroTrace getSelectedParmGenMacroTrace() {
        return this.pmtProvider.getBaseInstance(getSelectedTabIndexOfMacroRequestList());
    }

    /**
     * get tabIndex of current(default) value.<br>
     * current tab may be a tab with tabIndex 0 which means default tab.
     *
     * @return
     */
    public int getMacroRequestListTabsCurrentIndex() {
        return this.MacroRequestListTabsCurrentIndex;
    }

    /**
     * get ParmGenMacroTrace of current(default) tab<br>
     * current tab may be a tab with tabIndex 0 which means default tab.
     *
     * @return
     */
    public ParmGenMacroTrace getCurrentParmGenMacroTrace() {
        return getParmGenMacroTraceAtTabIndex(this.MacroRequestListTabsCurrentIndex);
    }

    /**
     * get ParmGenMacroTrace at specified tabIndex
     *
     * @param tabIndex
     * @return ParmGenMacroTrace or maybe null
     */
    public ParmGenMacroTrace getParmGenMacroTraceAtTabIndex(int tabIndex) {
        return this.pmtProvider.getBaseInstance(tabIndex);
    }
    
    /** 
     * get RequestList at specified tab index
     *
     * @param tabIndex
     * @return 
     */
    public List<PRequestResponse> getPRequestResponseListAtTabIndex(int tabIndex) {
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
        if (pmt != null) {
            return pmt.getPRequestResponseList();
        }
        return null;
    }
    
    @SuppressWarnings("unchecked")
    public void clear() {
        this.MacroRequestListTabsCurrentIndex = 0;
        displayInfo = new DisplayInfoOfRequestListTab();
        //JListをクリアするには、modelのremove & jListへModelセットが必須。
        // RequestListModel.removeAllElements();
        // RequestList.setModel(RequestListModel);
        requestJLists.forEach(list ->{
            DefaultListModel<String> defaultListModel = new DefaultListModel<>();
            defaultListModel.removeAllElements();
            list.setModel(defaultListModel);
        });
        JList<String> requestJList = requestJLists.get(0);
        requestJLists.clear();
        requestJLists.add(requestJList);

        // remove Tabs except default tab.
        while (MacroRequestListTabs.getTabCount() > 1) {
            int lastTabIndex = MacroRequestListTabs.getTabCount() - 1;
            MacroRequestListTabs.remove(lastTabIndex);
        }
        // Button for adding new Tab to JtabbedPane.
        addPlusTabButtonToRequestList();

        MacroRequest.setText("");
        MacroResponse.setText("");
        MacroComments.setText("");
        this.pmtProvider.clear();
        this.maxTabIndex = 0;
        ParmVars.Saved(false);
    }

    @SuppressWarnings("unchecked")
    public ParmGenMacroTrace addNewRequests(List<PRequestResponse> _rlist) {
        AppParmsIni pini;
        
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(this.MacroRequestListTabsCurrentIndex);

        if (_rlist != null && pmt != null) {
            
            if (pmt != null) {
                pmt.setRecords(_rlist);
            }
            Iterator<PRequestResponse> it = pmt.getIteratorOfRlist();
            int ii = 0;

            JList<String> requestJList = getSelectedRequestJList();
            if (requestJList != null) {
                DefaultListModel<String> listModel = (DefaultListModel<String>) requestJList.getModel();
                listModel.removeAllElements();
                while (it.hasNext()) {

                    //model.addRow(new Object[] {false, pini.url, pini.getIniValDsp(), pini.getLenDsp(), pini.getTypeValDsp(),pini.getAppValuesDsp(),pini.getCurrentValue()});
                    PRequestResponse pqr = it.next();
                    String url = pqr.request.getURL();
                    listModel.addElement((String.format("%03d",ii++) + '|' + url));
                }
                requestJList.setModel(listModel);
            }
        }

        return pmt;
    }


    /**
     * add PRequestResponses to ParmGenMacroTrace and add new tab which is created if necessary
     *
     * @param appParmAndSequence
     * @param maxTabIndex
     * @return
     */
    public ParmGenMacroTrace addNewRequestsToTabsPaneAtMaxTabIndex(ParmGenGSON.AppParmAndSequence appParmAndSequence, int maxTabIndex) {

        List<PRequestResponse> pRequestResponses= null;
        if (appParmAndSequence != null) {
            pRequestResponses = appParmAndSequence.pRequestResponses;
        }

        if (maxTabIndex < 0) {
            maxTabIndex = 0;
        }

        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(maxTabIndex);
        if (pmt == null) {
            pmt = pmtProvider.addNewBaseInstance();
            pmt.setUI(this);
        }

        if (appParmAndSequence != null && appParmAndSequence.appParmsIniList != null) {
            pmt.updateAppParmsIniAndClearCache(appParmAndSequence.appParmsIniList);
        }

        JList<String> requestJList = null;
        try {
            requestJList = getRequestJListAtTabIndex(maxTabIndex);
        } catch (Exception e) {
            // nothing to do with occuring exceptions.
        }
        if(requestJList == null) {
            requestJList = new javax.swing.JList<>();
            requestJList.setAutoscrolls(false);
            requestJList.addMouseListener(new java.awt.event.MouseAdapter() {
                public void mousePressed(java.awt.event.MouseEvent evt) {
                    RequestListMousePressed(evt);
                }
                public void mouseReleased(java.awt.event.MouseEvent evt) {
                    RequestListMouseReleased(evt);
                }
                public void mouseClicked(java.awt.event.MouseEvent evt) {
                    RequestListMouseClicked(evt);
                }
            });
            requestJList.addListSelectionListener(new javax.swing.event.ListSelectionListener() {
                public void valueChanged(javax.swing.event.ListSelectionEvent evt) {
                    RequestListValueChanged(evt);
                }
            });
            javax.swing.JScrollPane scrollPane = new JScrollPane();
            scrollPane.setAutoscrolls(true);
            scrollPane.setViewportView(requestJList);

            String tabIndexString = Integer.toString(maxTabIndex);

            MacroRequestListTabs.insertTab(tabIndexString, null, scrollPane, "", maxTabIndex);
            // setting close button on tab
            createCloseXbtnForTabbedPane(tabIndexString, maxTabIndex);

            requestJLists.add(requestJList);
        }
        requestJList.setCellRenderer((ListCellRenderer<Object>)new MacroBuilderUIRequestListRender(pmt));
        DefaultListModel<String> RequestListModel = new DefaultListModel<>();
        RequestListModel.clear();
        requestJList.setModel(RequestListModel);

        if (pRequestResponses != null && pmt != null) {

            if (pmt != null) {
                pmt.setRecords(pRequestResponses);
            }
            Iterator<PRequestResponse> it = pmt.getIteratorOfRlist();
            int ii = 0;


            if (requestJList != null) {
                DefaultListModel<String> listModel = (DefaultListModel<String>) requestJList.getModel();
                listModel.removeAllElements();
                while (it.hasNext()) {

                    //model.addRow(new Object[] {false, pini.url, pini.getIniValDsp(), pini.getLenDsp(), pini.getTypeValDsp(),pini.getAppValuesDsp(),pini.getCurrentValue()});
                    PRequestResponse pqr = it.next();
                    String url = pqr.request.getURL();
                    listModel.addElement((String.format("%03d",ii++) + '|' + url));
                }
                requestJList.setModel(listModel);
            }
        }

        displayInfo.clear();

        return pmt;
    }

    /**
     * update GUI contents with Current Selected request
     *
     */
    public void updateCurrentSelectedRequestListDisplayContents() {
        JList<String> requestJList = getSelectedRequestJList();
        if (requestJList != null) {
            int cpos = requestJList.getSelectedIndex();
            if (cpos != -1) { // current cpos request is displayed in MacroRequest.
                int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
                displayInfo.clear();
                displayInfo.selected_request_idx = cpos;
                messageViewTabbedPaneSelectedContentsLoad(selectedTabIndex);
            }
        }
    }

    public void Redraw() {
        //ListModel cmodel = RequestList.getModel();
        //RequestList.setModel(cmodel);
        logger4j.debug("RequestList.repaint called.");
        JList<String> requestJList = getSelectedRequestJList();
        if (requestJList != null) {
            requestJList.repaint();
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings({"unchecked","serial"})
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        PopupMenuForRequestList = new javax.swing.JPopupMenu();
        SendTo = new javax.swing.JMenu();
        Repeater = new javax.swing.JMenuItem();
        Scanner = new javax.swing.JMenuItem();
        Intruder = new javax.swing.JMenuItem();
        disableRequest = new javax.swing.JMenuItem();
        enableRequest = new javax.swing.JMenuItem();
        deleteRequest = new javax.swing.JMenuItem();
        showRequest = new javax.swing.JMenuItem();
        RequestEdit = new javax.swing.JPopupMenu();
        edit = new javax.swing.JMenuItem();
        restore = new javax.swing.JMenuItem();
        update = new javax.swing.JMenuItem();
        ResponseShow = new javax.swing.JPopupMenu();
        show = new javax.swing.JMenuItem();
        jScrollPane2 = new javax.swing.JScrollPane();
        jPanel4 = new javax.swing.JPanel();
        messageView = new javax.swing.JTabbedPane();
        requestView = new javax.swing.JPanel();
        requestScroller = new javax.swing.JScrollPane();
        MacroRequest = new javax.swing.JTextPane();
        responseView = new javax.swing.JPanel();
        responseScroller = new javax.swing.JScrollPane();
        MacroResponse = new javax.swing.JTextPane();
        trackingView = new javax.swing.JPanel();
        trackingScroller = new javax.swing.JScrollPane();
        MacroComments = new javax.swing.JTextArea();
        ParamTracking = new javax.swing.JButton();
        custom = new javax.swing.JButton();
        ClearMacro = new javax.swing.JButton();
        Load = new javax.swing.JButton();
        Save = new javax.swing.JButton();
        StartScan = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jPanel5 = new javax.swing.JPanel();
        CBinheritFromCache = new javax.swing.JCheckBox();
        jLabel4 = new javax.swing.JLabel();
        jPanel6 = new javax.swing.JPanel();
        TrackMode = new javax.swing.JComboBox<>();
        jLabel3 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        jCheckBox2 = new javax.swing.JCheckBox();
        waitsec = new javax.swing.JTextField();
        MBfromStepNo = new javax.swing.JCheckBox();
        jLabel1 = new javax.swing.JLabel();
        jPanel7 = new javax.swing.JPanel();
        FinalResponse = new javax.swing.JCheckBox();
        requestListNum = new javax.swing.JLabel();
        subSequenceScanLimit = new javax.swing.JTextField();
        jCheckBox1 = new javax.swing.JCheckBox();
        MBtoStepNo = new javax.swing.JCheckBox();
        MBmonitorofprocessing = new javax.swing.JCheckBox();
        UpSelected = new javax.swing.JButton();
        DownSelected = new javax.swing.JButton();
        MacroRequestListTabs = new javax.swing.JTabbedPane();
        jScrollPane1 = new javax.swing.JScrollPane();
        RequestList = new javax.swing.JList<>();


        SendTo.setText(bundle.getString("MacroBuilderUI.SENDTO.text")); // NOI18N

        Repeater.setText(bundle.getString("MacroBuilderUI.REPEATER.text")); // NOI18N
        Repeater.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RepeaterActionPerformed(evt);
            }
        });
        SendTo.add(Repeater);

        Scanner.setText(bundle.getString("MacroBuilderUI.SCANNER.text")); // NOI18N
        Scanner.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ScannerActionPerformed(evt);
            }
        });
        SendTo.add(Scanner);

        Intruder.setText(bundle.getString("MacroBuilderUI.INTRUDER.text")); // NOI18N
        Intruder.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                IntruderActionPerformed(evt);
            }
        });
        SendTo.add(Intruder);

        PopupMenuForRequestList.add(SendTo);

        disableRequest.setText(bundle.getString("MacroBuilderUI.DISABLEREQUEST.text")); // NOI18N
        disableRequest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                disableRequestActionPerformed(evt);
            }
        });
        PopupMenuForRequestList.add(disableRequest);

        enableRequest.setText(bundle.getString("MacroBuilderUI.ENABLEREQUEST.text")); // NOI18N
        enableRequest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                enableRequestActionPerformed(evt);
            }
        });
        PopupMenuForRequestList.add(enableRequest);

        deleteRequest.setText(bundle.getString("MacroBuilderUI.DELETEREQUEST.text")); // NOI18N
        deleteRequest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteRequestActionPerformed(evt);
            }
        });
        PopupMenuForRequestList.add(deleteRequest);

        showRequest.setText(bundle.getString("MacroBuilderUI.showRequest.text")); // NOI18N
        showRequest.addActionListener(new ActionListener() {
            final ExtensionAutoMacroBuilder ext = MacroBuilderUI.this.extensionAutoMacroBuilder;
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                View.getSingleton()
                        .getWorkbench().showPanel(ext.getMessageViewStatusPanel());
            }
        });
        PopupMenuForRequestList.add(showRequest);

        edit.setText(bundle.getString("MacroBuilderUI.REQUESTEDIT.text")); // NOI18N
        edit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editActionPerformed(evt);
            }
        });
        RequestEdit.add(edit);

        restore.setText(bundle.getString("MacroBuilderUI.restore.text")); // NOI18N
        restore.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                restoreActionPerformed(evt);
            }
        });
        RequestEdit.add(restore);

        update.setText(bundle.getString("MacroBuilderUI.update.text")); // NOI18N
        update.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                updateActionPerformed(evt);
            }
        });
        RequestEdit.add(update);

        show.setText(bundle.getString("MacroBuilderUI.RESPONSESHOW.text")); // NOI18N
        show.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                showActionPerformed(evt);
            }
        });
        ResponseShow.add(show);

        setPreferredSize(new java.awt.Dimension(873, 850));

        jPanel4.setPreferredSize(new java.awt.Dimension(871, 1500));

        descriptionVacantArea = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
        JLabel messageAreaMovedToStatusLabel = new JLabel();
        messageAreaMovedToStatusLabel.putClientProperty("html.disable", Boolean.FALSE);
        messageAreaMovedToStatusLabel.setText(bundle.getString("MacroBuilderUI.describeMessageView"));
        descriptionVacantArea.add(messageAreaMovedToStatusLabel);
        LineBorder lborder = new LineBorder(Color.BLACK, 2, false);
        descriptionVacantArea.setBorder(lborder);

        messageView.setPreferredSize(new java.awt.Dimension(847, 300));
        messageView.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                messageViewStateChanged(evt);
            }
        });

        MacroRequest.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                MacroRequestMousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                MacroRequestMouseReleased(evt);
            }
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                MacroRequestMouseClicked(evt);
            }
        });
        requestScroller.setViewportView(MacroRequest);

        javax.swing.GroupLayout requestViewLayout = new javax.swing.GroupLayout(requestView);
        requestView.setLayout(requestViewLayout);
        requestViewLayout.setHorizontalGroup(
            requestViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(requestViewLayout.createSequentialGroup()
                .addGap(0, 0, 0)
                .addComponent(requestScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE)
                .addGap(0, 0, 0))
        );
        requestViewLayout.setVerticalGroup(
            requestViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(requestScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 302, Short.MAX_VALUE)
        );

        messageView.addTab(bundle.getString("MacroBuilderUI.messageViewToAddRequestTabTitle.text"), requestView); // NOI18N

        MacroResponse.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                MacroResponseMousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                MacroResponseMouseReleased(evt);
            }
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                MacroResponseMouseClicked(evt);
            }
        });
        responseScroller.setViewportView(MacroResponse);

        javax.swing.GroupLayout responseViewLayout = new javax.swing.GroupLayout(responseView);
        responseView.setLayout(responseViewLayout);
        responseViewLayout.setHorizontalGroup(
            responseViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(responseScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE)
        );
        responseViewLayout.setVerticalGroup(
            responseViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(responseScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 302, Short.MAX_VALUE)
        );

        messageView.addTab(bundle.getString("MacroBuilderUI.messageViewToAddResponseTabTitle.text"), responseView); // NOI18N

        trackingScroller.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        MacroComments.setColumns(20);
        MacroComments.setLineWrap(true);
        MacroComments.setRows(5);
        trackingScroller.setViewportView(MacroComments);

        javax.swing.GroupLayout trackingViewLayout = new javax.swing.GroupLayout(trackingView);
        trackingView.setLayout(trackingViewLayout);
        trackingViewLayout.setHorizontalGroup(
            trackingViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(trackingScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE)
        );
        trackingViewLayout.setVerticalGroup(
            trackingViewLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(trackingScroller, javax.swing.GroupLayout.DEFAULT_SIZE, 302, Short.MAX_VALUE)
        );

        messageView.addTab(
                bundle.getString("MacroBuilderUI.messageViewToAddTrackingTabTitle.text"),
                null,
                trackingView,
                bundle.getString("MacroBuilderUI.messageViewToAddTrackingTabToolTop.text")); // NOI18N


        messageViewPanel = new JPanel(new BorderLayout());
        messageViewPanel.add(messageView);

        ParamTracking.setText(bundle.getString("MacroBuilderUI.ParamTrackingBtn.text")); // NOI18N
        ParamTracking.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ParamTrackingActionPerformed(evt);
            }
        });

        custom.setText(bundle.getString("MacroBuilderUI.CUSTOM.text")); // NOI18N
        custom.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                customActionPerformed(evt);
            }
        });

        ClearMacro.setText(bundle.getString("MacroBuilderUI.ClearMacroBtn.text")); // NOI18N
        ClearMacro.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ClearMacroActionPerformed(evt);
            }
        });

        Load.setText(bundle.getString("MacroBuilderUI.LOAD.text")); // NOI18N
        Load.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                LoadActionPerformed(evt);
            }
        });

        Save.setText(bundle.getString("MacroBuilderUI.SAVE.text")); // NOI18N
        Save.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SaveActionPerformed(evt);
            }
        });

        StartScan.setText(bundle.getString("MacroBuilderUI.StartScan.text")); // NOI18N
        StartScan.setEnabled(false);
        StartScan.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                StartScanActionPerformed(evt);
            }
        });

        jLabel2.setText(bundle.getString("MacroBuilderUI.MacroRequestListLabel2.text")); // NOI18N

        jPanel5.setBorder(javax.swing.BorderFactory.createTitledBorder(bundle.getString("MacroBuilderUI.TakeOverCache.text"))); // NOI18N

        CBinheritFromCache.setSelected(true);
        CBinheritFromCache.setText(bundle.getString("MacroBuilderUI.TakeOverCacheCheckBox.text")); // NOI18N
        CBinheritFromCache.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CBinheritFromCacheActionPerformed(evt);
            }
        });

        jLabel4.putClientProperty("html.disable", Boolean.FALSE);
        jLabel4.setText(bundle.getString("MacroBuilderUI.TakeOverInfoLabel.text")); // NOI18N

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel5Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(CBinheritFromCache, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(jPanel5Layout.createSequentialGroup()
                        .addGap(29, 29, 29)
                        .addComponent(jLabel4)))
                .addContainerGap())
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel5Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(CBinheritFromCache)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel4, javax.swing.GroupLayout.DEFAULT_SIZE, 29, Short.MAX_VALUE)
                .addContainerGap())
        );

        jPanel6.setBorder(javax.swing.BorderFactory.createTitledBorder(bundle.getString("MacroBuilderUI.TrackingParamBorder.text"))); // NOI18N

        TrackMode.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "replace", "baseline" }));
        TrackMode.setToolTipText("<HTML>\n[baseline] mode:<BR>\nthe token parameter value is changed only the baseline part , so which you can tamper by burp tools.<BR>\n<BR>\nyou can add test pattern in parameter value, e.g. '||'<BR>\nex.<BR>\ntoken=8B12C123'||' ===> token=A912D8VC'||'<BR><BR>\nNote:  In baseline mode,if you encounter problem which fails tracking tokens, you should select \"■update baseline■\" menu in BurpTool's popup menu.<BR>\n<BR>\n[replace] mode:<BR>\nthe token parameter value is completely replaced with tracking value, so which you cannot tamper by burp tools.<BR>\nex.<BR>\ntoken=8B12C123'||' ===> token=A912D8VC<BR>");
        TrackMode.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                TrackModeActionPerformed(evt);
            }
        });

        jLabel3.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        //jLabel3.setText("<HTML>\n<DL>\n<BR>\n<LI>baseline(experimental): you can test(tamper) tracking tokens<BR> with scanner/intruder which has baseline request.\n<LI>replace(default): Tracking tokens is completely replaced with extracted value from previous page's response.\n<BR><BR>* For Details , refer ?button in the \"baseline/replace mode\" section. \n<DL>\n</HTML>");
        jLabel3.setText(bundle.getString("MacroBuilderUI.TrackingParamterConfig.text"));
        jLabel3.setVerticalAlignment(javax.swing.SwingConstants.TOP);
        //LineBorder lborder = new LineBorder(Color.RED, 2, false);
        //jLabel3.setBorder(lborder);


        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel6Layout = new javax.swing.GroupLayout(jPanel6);
        jPanel6.setLayout(jPanel6Layout);
        jPanel6Layout.setHorizontalGroup(
            jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel6Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(TrackMode, javax.swing.GroupLayout.PREFERRED_SIZE, 101, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 21, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel6Layout.setVerticalGroup(
            jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel6Layout.createSequentialGroup()
                .addContainerGap(14, Short.MAX_VALUE)
                .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel6Layout.createSequentialGroup()
                        .addComponent(TrackMode, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(39, 39, 39)
                        .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jCheckBox2.setText("WaitTimer(sec)");
        jCheckBox2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBox2ActionPerformed(evt);
            }
        });

        waitsec.setText("0");

        MBfromStepNo.setText(bundle.getString("MacroBuilderUI.FromStepBtn.text")); // NOI18N
        MBfromStepNo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                MBfromStepNoActionPerformed(evt);
            }
        });

        jLabel1.setText("Other Options(Usually, you do not need chage options below.)");

        jPanel7.setBorder(javax.swing.BorderFactory.createTitledBorder("Pass response of subsequent request  back as the result of scan/resend request"));

        FinalResponse.setSelected(true);
        FinalResponse.setText(bundle.getString("MacroBuilderUI.FINAL RESPONSE.text")); // NOI18N
        FinalResponse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FinalResponseActionPerformed(evt);
            }
        });

        requestListNum.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        requestListNum.setText("subsequence scan limit");

        subSequenceScanLimit.setText("-1");
        subSequenceScanLimit.setToolTipText("maximum number of subsequent requests after scan/resend request currently being tested.");
        subSequenceScanLimit.setInputVerifier(new IntegerInputVerifier());
        subSequenceScanLimit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                subSequenceScanLimitActionPerformed(evt);
            }
        });

        jCheckBox1.setText("scan all from current target to [Subsequence scan limit]/[Final Response] ");
        jCheckBox1.setEnabled(false);
        jCheckBox1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBox1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel7Layout = new javax.swing.GroupLayout(jPanel7);
        jPanel7.setLayout(jPanel7Layout);
        jPanel7Layout.setHorizontalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jCheckBox1, javax.swing.GroupLayout.PREFERRED_SIZE, 569, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel7Layout.createSequentialGroup()
                        .addComponent(FinalResponse, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(53, 53, 53)
                        .addComponent(requestListNum, javax.swing.GroupLayout.PREFERRED_SIZE, 178, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(subSequenceScanLimit, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel7Layout.setVerticalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel7Layout.createSequentialGroup()
                .addGroup(jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.CENTER)
                    .addComponent(FinalResponse)
                    .addComponent(requestListNum)
                    .addComponent(subSequenceScanLimit, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jCheckBox1))
        );

        MBtoStepNo.setText(bundle.getString("MacroBuilderUI.MBtoStepNo.text")); // NOI18N

        MBmonitorofprocessing.setText(bundle.getString("MacroBuilderUI.MBmonitorofprocessing.text")); // NOI18N
        MBmonitorofprocessing.setEnabled(false);
        MBmonitorofprocessing.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                MBmonitorofprocessingActionPerformed(evt);
            }
        });

        UpSelected.setText(bundle.getString("MacroBuilderUI.UpSelected.text")); // NOI18N
        UpSelected.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                UpSelectedActionPerformed(evt);
            }
        });

        DownSelected.setText(bundle.getString("MacroBuilderUI.DownSelected.text")); // NOI18N
        DownSelected.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DownSelectedActionPerformed(evt);
            }
        });

        MacroRequestListTabs.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                MacroRequestListTabsStateChanged(evt);
            }
        });

        jScrollPane1.setAutoscrolls(true);

        RequestList.setModel(new javax.swing.AbstractListModel<String>() {
            String[] strings = { "Item 1", "Item 2", "Item 3", "Item 4", "Item 5" };
            public int getSize() { return strings.length; }
            public String getElementAt(int i) { return strings[i]; }
        });
        RequestList.setAutoscrolls(false);
        RequestList.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                RequestListMousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                RequestListMouseReleased(evt);
            }
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                RequestListMouseClicked(evt);
            }
        });
        RequestList.addListSelectionListener(new javax.swing.event.ListSelectionListener() {
            public void valueChanged(javax.swing.event.ListSelectionEvent evt) {
                RequestListValueChanged(evt);
            }
        });
        jScrollPane1.setViewportView(RequestList);

        MacroRequestListTabs.addTab("0", jScrollPane1);

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 826, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                        .addComponent(descriptionVacantArea, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addContainerGap())
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 402, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addComponent(MacroRequestListTabs))
                        .addGap(18, 18, 18)
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(custom, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(ClearMacro, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(ParamTracking, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(Load, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(Save, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(StartScan, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(UpSelected, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(DownSelected, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addContainerGap())
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addComponent(jCheckBox2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGap(18, 18, 18)
                                .addComponent(waitsec, javax.swing.GroupLayout.PREFERRED_SIZE, 68, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(150, 150, 150))
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addComponent(MBfromStepNo, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(26, 26, 26)))
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(MBtoStepNo, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(MBmonitorofprocessing, javax.swing.GroupLayout.PREFERRED_SIZE, 405, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jPanel7, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jSeparator1, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jPanel6, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jPanel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(26, 26, 26))))
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addGap(23, 23, 23)
                .addComponent(jLabel2)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGap(42, 42, 42)
                        .addComponent(ParamTracking)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(custom)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(ClearMacro)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(Load)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(Save)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(UpSelected)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(DownSelected)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(StartScan))
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGap(18, 18, 18)
                        .addComponent(MacroRequestListTabs, javax.swing.GroupLayout.PREFERRED_SIZE, 298, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(28, 28, 28)
                .addComponent(descriptionVacantArea, javax.swing.GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPanel5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPanel6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jPanel7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(73, 73, 73)
                .addComponent(jLabel1)
                .addGap(18, 18, 18)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jCheckBox2)
                    .addComponent(MBmonitorofprocessing)
                    .addComponent(waitsec, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(43, 43, 43)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(MBfromStepNo)
                    .addComponent(MBtoStepNo))
                .addContainerGap(121, Short.MAX_VALUE))
        );

        jScrollPane2.setViewportView(jPanel4);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 873, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 1437, Short.MAX_VALUE)
        );

        getAccessibleContext().setAccessibleName("");
    }// </editor-fold>//GEN-END:initComponents

    private void customActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_customActionPerformed
        /*
        * Open Custom Parameter Config dialog
        */
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        List<String> poslist = requestJList.getSelectedValuesList();
        ArrayList<PRequestResponse> messages = new ArrayList<PRequestResponse>();
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
        if (pmt == null) return;
        List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
        if (prequestResponseList != null) {
            for (String s : poslist) {
                String[] values = s.split("[|]", 0);
                if (values.length > 0) {
                    int i = Integer.parseInt(values[0]);
                    PRequestResponse pqr = prequestResponseList.get(i);
                    pqr.setMacroPos(i);
                    messages.add(pqr);
                }
            }
        }
            
        if(ParmGen.twin==null){
            pmt.updateAppParmsIniAndClearCache(null);
            ParmGen.twin = new ParmGenTop(pmt, new ParmGenGSONSaveV2(this.getParmGenMacroTraceProvider(),
                    messages)
                    );
        }

        ParmGen.twin.VisibleWhenJSONSaved(this);
        updateSelectedTabIndex();


    }//GEN-LAST:event_customActionPerformed

    private void MacroRequestLoadContents(int selectedTabIndexOfRequestList){
        if (displayInfo != null && displayInfo.selected_request_idx!=-1&&!displayInfo.isLoadedMacroRequestContents) {
            
            List<PRequestResponse> prequestResponseList = getPRequestResponseListAtTabIndex(selectedTabIndexOfRequestList);
            PRequestResponse pqr = prequestResponseList.get(displayInfo.selected_request_idx);

            ParmGenTextDoc reqdoc = new ParmGenTextDoc(MacroRequest);

            reqdoc.setRequestChunks(pqr.request);

            displayInfo.isLoadedMacroRequestContents = true;
        }
    }
    
    private void MacroResponseLoadContents(int selectedTabIndexOfRequestList){
        if (displayInfo != null && displayInfo.selected_request_idx!=-1&&!displayInfo.isLoadedMacroResponseContents) {
            List<PRequestResponse> prequestResponseList = getPRequestResponseListAtTabIndex(selectedTabIndexOfRequestList);
            PRequestResponse pqr = prequestResponseList.get(displayInfo.selected_request_idx);
            
            ParmGenTextDoc resdoc = new ParmGenTextDoc(MacroResponse);
            resdoc.setResponseChunks(pqr.response);
            displayInfo.isLoadedMacroResponseContents = true;
        }
    }
    
    private void MacroCommentLoadContents(int selectedTabIndexOfRequestList){
        if (displayInfo != null && displayInfo.selected_request_idx!=-1&&!displayInfo.isLoadedMacroCommentContents) {
            List<PRequestResponse> prequestResponseList = getPRequestResponseListAtTabIndex(selectedTabIndexOfRequestList);
            PRequestResponse pqr = prequestResponseList.get(displayInfo.selected_request_idx);
            MacroComments.setText(pqr.getComments());
            displayInfo.isLoadedMacroCommentContents = true;
        }
    }

    /**
     * load when tabbed pane content is selected
     *
     * @param selectedTabIndexOfRequestList
     */
    private void messageViewTabbedPaneSelectedContentsLoad(int selectedTabIndexOfRequestList){
        int selIndex = messageView.getSelectedIndex();//tabbedpanes selectedidx 0start..
        switch(selIndex){
            case 0:
                MacroRequestLoadContents(selectedTabIndexOfRequestList);
                break;
            case 1:
                MacroResponseLoadContents(selectedTabIndexOfRequestList);
                break;
            case 2:
                MacroCommentLoadContents(selectedTabIndexOfRequestList);
                break;
            default:
                MacroRequestLoadContents(selectedTabIndexOfRequestList);
                break;
        }
    }
    
    private void RequestListValueChanged(javax.swing.event.ListSelectionEvent evt) {//GEN-FIRST:event_RequestListValueChanged
        /*
         * called when MacroRequestList item is selected
         */
        // TODO add your handling code here:
        // we need magical coding below,,,
        if (evt.getValueIsAdjusting()) {
            // The user is still manipulating the selection.
            return;
        }

        JList<String> requestJList = getSelectedRequestJList();
        if (requestJList == null) return;
        logger4j.debug("RequestListValueChanged Start...");
        int pos = requestJList.getSelectedIndex();
        if (pos != -1) {
            logger4j.debug("RequestListValueChanged selected pos:" + pos);
            //
            int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
            displayInfo.clear();
            displayInfo.selected_request_idx = pos;
            messageViewTabbedPaneSelectedContentsLoad(selectedTabIndex);
        } else {
            logger4j.debug("RequestListValueChanged noselect pos:" + pos);
        }
        logger4j.debug("RequestListValueChanged done");
    }//GEN-LAST:event_RequestListValueChanged

    private void CBinheritFromCacheActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CBinheritFromCacheActionPerformed
        /*
         * checkbox: at the start of sequence, session cache/Token value ia set from cache
         */
        // TODO add your handling code here:
        pmtProvider.setCBInheritFromCache(CBinheritFromCache.isSelected());
    }//GEN-LAST:event_CBinheritFromCacheActionPerformed

    private void jCheckBox2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBox2ActionPerformed
        // TODO add your handling code here:
        ParmGenMacroTrace pmt = getSelectedParmGenMacroTrace();
        if (pmt != null) {
            if(jCheckBox2.isSelected()){
                pmtProvider.setWaitTimer(waitsec.getText());
            }else{
                pmtProvider.setWaitTimer("0");
            }
        }
    }//GEN-LAST:event_jCheckBox2ActionPerformed

    private void FinalResponseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FinalResponseActionPerformed
        // TODO add your handling code here:
        pmtProvider.setCBFinalResponse(FinalResponse.isSelected());
    }//GEN-LAST:event_FinalResponseActionPerformed

    private void RequestListMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_RequestListMousePressed
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {
            PopupMenuForRequestList.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_RequestListMousePressed

    private void disableRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_disableRequestActionPerformed
        /*
         * Disable selected request in ParmGenMacroTrace::rlist. this action does not affect ParmGenMacroTrace::originalrlist
         */
        // TODO add your handling code here:
        int tabIndex = getSelectedTabIndexOfMacroRequestList();
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (pos != -1) {
                pmt.DisableRequest(pos);
            }
            Redraw();
        }
    }//GEN-LAST:event_disableRequestActionPerformed

    private void enableRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_enableRequestActionPerformed
        /*
         * Enable selected request in ParmGenMacroTrace::rlist. this action does not affect ParmGenMacroTrace::originalrlist
         */
        // TODO add your handling code here:
        int tabIndex = getSelectedTabIndexOfMacroRequestList();

        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (pos != -1) {
                pmt.EnableRequest(pos);
            }
            Redraw();
        }

    }//GEN-LAST:event_enableRequestActionPerformed

    private void RequestListMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_RequestListMouseClicked
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {
            PopupMenuForRequestList.show(evt.getComponent(), evt.getX(), evt.getY());
        }
        if ((evt.getModifiersEx() & InputEvent.BUTTON1_DOWN_MASK) != 0) { // left button clicked
            JList<String> requestJList = getSelectedRequestJList();
            if (requestJList == null) return;
            int sidx = requestJList.locationToIndex(evt.getPoint());
            if (sidx > -1) {
                logger4j.debug("RequestList mouse left button clicked: sidx:" + sidx);
                if (displayInfo.selected_request_idx == sidx){
                    requestJList.clearSelection();
                    requestJList.setSelectedIndex(sidx);
                    logger4j.debug("clearSelection and setSelectidx:" + sidx);
                }
            }
        }
    }//GEN-LAST:event_RequestListMouseClicked

    private void RequestListMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_RequestListMouseReleased
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {
            PopupMenuForRequestList.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_RequestListMouseReleased

    @SuppressWarnings("serial")
    private void ParamTrackingActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ParamTrackingActionPerformed
        // TODO add your handling code here:
        //fileChooser起動
    	File cfile = new File(ParmVars.getParmFile());
        String dirname = cfile.getParent();
        JFileChooser jfc = new JFileChooser(dirname) {

            @Override
            public void approveSelection() {
                File f = getSelectedFile();
                if (f.exists() && getDialogType() == SAVE_DIALOG) {
                    String m = String.format(
                            "<html>%s already exists.<br>Do you want to replace it?",
                            f.getAbsolutePath());
                    int rv = JOptionPane.showConfirmDialog(
                            this, m, "Save As", JOptionPane.YES_NO_OPTION);
                    if (rv != JOptionPane.YES_OPTION) {
                        return;
                    }
                }
                super.approveSelection();
            }
        };
        ParmGenMacroTrace pmt = getSelectedParmGenMacroTrace();
        if (pmt == null) return;
        ParmFileFilter pFilter = new ParmFileFilter();
        jfc.setFileFilter(pFilter);
        List<PRequestResponse> orglist = pmt.getOriginalPRequestResponseList();
        if (jfc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION && orglist!=null) {

            //code to handle choosed file here.
            File file = jfc.getSelectedFile();
            String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");
            if(!pFilter.accept(file)){//拡張子無しの場合は付与
                name += ".json";
            }
            ParmVars.setParmFile(name);
            //エンコードの設定
            //ParmVars.encエンコードの決定
            //先頭ページのレスポンスのcharsetを取得
            PRequestResponse toppage = orglist.get(0);
            String tcharset = toppage.response.getCharset();
            //ParmVars.enc = Encode.getEnum(tcharset);

            String tknames[] = {//予約語 reserved token names
                "PHPSESSID",
                "JSESSIONID",
                "SESID",
                "TOKEN",
                "_CSRF_TOKEN",
                "authenticity_token",
                "NONCE",
                "access_id",
                "fid",
                "ethna_csrf",
                "uniqid",
                "oauth"
            };

            ArrayList<ParmGenResTokenCollections> urltokens = new ArrayList<>();// extracted token parameter from Responses.
            Pattern patternw32 = ParmGenUtil.Pattern_compile("\\w{32}");

            List<AppParmsIni> newparms = new ArrayList<AppParmsIni>();// generating parameter for tracking
            PRequestResponse respqrs = null;
            //int row = 0;
            int pos = 0;

            for (PRequestResponse pqrs : orglist) {
                HashMap<ParmGenTrackingToken, String> addedtokens = new HashMap<ParmGenTrackingToken, String>();// tokens already extracted from urltokens
                for(ListIterator<ParmGenResTokenCollections> it = urltokens.listIterator(urltokens.size()); it.hasPrevious();){//urltokens: extracted tokenHashMap from Response.
                    //for loop order: fromStepno in descending order(hasPrevious)

                    ParmGenResTokenCollections resTokenCollections = it.previous();
                    Encode resEncode = resTokenCollections.resEncode;
                    int fromStepNo = resTokenCollections.fromStepNo;

                    ArrayList<ParmGenTrackingToken> requesttokenlist = new ArrayList<ParmGenTrackingToken>();// response tokens that matched request parameter.

                    // parse request for extracting JSON request parameters.
                    ParmGenGSONDecoder reqjdecoder = new ParmGenGSONDecoder(pqrs.request.getBodyStringWithoutHeader());
                    List<ParmGenToken> reqjtklist = reqjdecoder.parseJSON2Token();

                    ParmGenRequestToken _QToken = null;
                    ParmGenToken _RToken = null;
                    for(ParmGenToken reqtkn : reqjtklist){ // search JSON Name or Value in response

                        ParmGenToken foundResToken = resTokenCollections.findResponseToken(reqtkn);

                        if(foundResToken != null){
                            //We found json tracking parameter in request.
                            _RToken = foundResToken;
                            _QToken = new ParmGenRequestToken(reqtkn);

                            ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, null);
                            if(!addedtokens.containsKey(tracktoken)){
                                requesttokenlist.add(tracktoken);
                                addedtokens.put(tracktoken, "");
                            }
                        }
                    }

                    // ParmGenRequestToken query_token = pqrs.request.getRequestQueryToken(token);
                    // ParmGenRequestToken body_token = pqrs.request.getRequestBodyToken(token);
                    for(ParmGenRequestToken requestToken: pqrs.request.getRequestTokens()) {
                        ParmGenToken foundResToken = resTokenCollections.findResponseToken(requestToken);

                        if (foundResToken != null) {

                            //add a token to  Query / Body Request parameter.
                            switch (foundResToken.getTokenKey().GetTokenType()) {
                                case ACTION:
                                case HREF:

                                    ParmGenParseURL _psrcurl = new ParmGenParseURL(foundResToken.getTokenValue().getURL());
                                    ParmGenParseURL _pdesturl = new ParmGenParseURL(pqrs.request.getURL());
                                    String srcurl = _psrcurl.getPath();
                                    String desturl = _pdesturl.getPath();
                                    logger4j.debug("srcurl|desturl:[" + srcurl + "]|[" + desturl + "]");
                                    if (desturl.indexOf(srcurl) != -1) {// ACTION SRC/HREF attribute's path == destination request path
                                        _RToken = foundResToken;
                                        if (requestToken != null) {
                                            //We found same name/value ACTION/HREF's query paramter in request's query parameter.
                                            _QToken = requestToken;
                                            ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, null);
                                            if (!addedtokens.containsKey(tracktoken)) {
                                                requesttokenlist.add(tracktoken);
                                                addedtokens.put(tracktoken, "");
                                            }
                                        }
                                    }
                                    break;
                                default:
                                    _RToken = foundResToken;
                                    if (requestToken != null) {
                                        //We found same name/value INPUT TAG(<INPUT type=...>)'s paramter in request's query parameter.
                                        _QToken = requestToken;
                                        ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, null);
                                        if (!addedtokens.containsKey(tracktoken)) {
                                            requesttokenlist.add(tracktoken);
                                            addedtokens.put(tracktoken, "");
                                        }
                                    }
                                    break;
                            }
                        }
                    }

                    //bearer/cookie header parameter
                    ArrayList<HeaderPattern> hlist = pqrs.request.hasHeaderMatchedValue(resTokenCollections);
                    if(hlist!=null&&hlist.size()>0){
                        for(HeaderPattern hpattern: hlist){
                            _QToken = hpattern.getQToken();
                            _RToken = hpattern.getFoundResponseToken();
                            ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, hpattern.getTokenValueRegex());
                            if (!addedtokens.containsKey(tracktoken)) {
                                requesttokenlist.add(tracktoken);
                                addedtokens.put(tracktoken, "");
                            }
                        }
                    }

                    if (requesttokenlist.size()>0) {//tracking parameters are generated from requesttokenlist.
                        //パラメータ生成
                        AppParmsIni aparms = new AppParmsIni();//add new record
                        //request URL
                        //String TargetURLRegex = ".*" + pqrs.request.getPath() + ".*";
                        String TargetURLRegex = ".*";//SetTo any
                        //boolean isformdata = pqrs.request.isFormData();
                        aparms.setUrl(TargetURLRegex);
                        aparms.setLen(4);//default
                        aparms.setTypeVal(AppParmsIni.T_TRACK);
                        aparms.setIniVal(0);
                        aparms.setMaxVal(0);
                        aparms.setCsvName("");
                        aparms.initPause(false);
                        // aparms.parmlist = new ArrayList<AppValue>();
                        if(MBfromStepNo.isSelected()){
                            aparms.setTrackFromStep(fromStepNo);
                        }else{
                            aparms.setTrackFromStep(-1);
                        }

                        if(MBtoStepNo.isSelected()){
                            aparms.setSetToStep(pos);
                        }else{
                            aparms.setSetToStep(ParmVars.TOSTEPANY);
                        }

                        for (ParmGenTrackingToken PGTtkn : requesttokenlist) {
                            AppValue apv = new AppValue();

                            _QToken = PGTtkn.getRequestToken();
                            _RToken = PGTtkn.getResponseToken();
                            ParmGenRequestTokenKey.RequestParamType rptype = _QToken.getKey().getRequestParamType();
                            String token = _RToken.getTokenKey().getName();
                            //body/query/header
                            String valtype = "query";

                            switch(rptype){
                                case Query:
                                    break;
                                case Header:
                                    valtype = "header";
                                    break;
                                default:
                                    valtype = "body";
                                    break;
                            }

                            apv.setValPart(valtype);
                            apv.clearNoCount();
                            apv.setCsvpos(-1);
                            // (?:[&=?]+|^)token=(value)

                            String value = _RToken.getTokenValue().getValue();
                            apv.setResFetchedValue(value);
                            int len = value.length();// For Future use. len is currently No Used. len: token value length. May be,we should be specified len into regex's token value length
                            String paramname = token;
                            if(_QToken!=null){// May be Request Token name(_RToken's Name) != Response Token name(_QToken's name)
                                int rlen = _QToken.getValue().length();
                                if(len<rlen) len = rlen;
                                paramname = _QToken.getKey().getName();
                            }

                            apv.setUrlEncode(true);//www-form-urlencoded default

                            String regex = "(?:[&=?]|^)" + ParmGenUtil.escapeRegexChars(paramname) + "=([^&=\\r\\n ;#]+)";//default regex. It may be necessary to set the embedding token value length.
                            switch(rptype){
                                case Form_data:
                                    regex = "(?:[A-Z].* name=\"" + ParmGenUtil.escapeRegexChars(paramname) + "\".*(?:\\r|\\n|\\r\\n))(?:[A-Z].*(?:\\r|\\n|\\r\\n)){0,}(?:\\r|\\n|\\r\\n)(?:.*?)(.+)";
                                    apv.setUrlEncode(false);
                                    break;
                                case Json:
                                    regex = "\"" + ParmGenUtil.escapeRegexChars(paramname) + "\"(?:[\\t \\r\\n]*):(?:[\\t\\[\\r\\n ]*)\"(.+?)\"(?:[\\t \\]\\r\\n]*)(?:,|})";
                                    List<String> jsonmatchlist = ParmGenUtil.getRegexMatchGroups(regex, pqrs.request.getBodyStringWithoutHeader());
                                    boolean jsonmatched = false;
                                    String jsonvalue = _QToken.getValue();

                                    if(jsonmatchlist!=null&&jsonmatchlist.size()>0){
                                        jsonmatched = true;
                                    }
                                    if(!jsonmatched){// "key": value
                                        regex ="\"" + ParmGenUtil.escapeRegexChars(paramname) + "\"(?:[\\t \\r\\n]*):(?:[\\t\\[\\r\\n ]*)([^,:{}\\\"]+?)(?:[\\t \\]\\r\\n]*)(?:,|})";
                                        jsonmatchlist = ParmGenUtil.getRegexMatchGroups(regex, pqrs.request.getBodyStringWithoutHeader());

                                        if(jsonmatchlist!=null&&jsonmatchlist.size()>0){
                                            jsonmatched = true;
                                        }
                                    }
                                    apv.setUrlEncode(false);
                                    break;
                                case X_www_form_urlencoded:
                                    regex = "(?:[&=?]|^)" + ParmGenUtil.escapeRegexChars(paramname) + "=([^&=]+)";
                                    break;
                                case Header:
                                    regex = PGTtkn.getRegex();
                                    apv.setUrlEncode(false);
                                    break;
                            }



                            String encodedregex = regex;
                            try {
                                encodedregex = URLEncoder.encode(regex, JSONFileIANACharsetName);
                            } catch (UnsupportedEncodingException ex) {
                                Logger.getLogger(MacroBuilderUI.class.getName()).log(Level.SEVERE, null, ex);

                            }
                            apv.setURLencodedVal(encodedregex);
                            //apv.setresURL(".*" + restoken.request.getPath() + ".*");
                            apv.setresURL(".*");//TrackFrom any URL
                            apv.setresRegexURLencoded("");
                            int resvalpart = AppValue.V_AUTOTRACKBODY;
                            switch (_RToken.getTokenKey().GetTokenType()) {
                            case LOCATION:
                                resvalpart = AppValue.V_HEADER;
                                break;
                            case XCSRF:
                                break;
                            default:
                                break;

                            }
                            apv.setresPartType(apv.getValPart(resvalpart));
                            apv.setResRegexPos(_RToken.getTokenKey().getFcnt());
                            apv.setToken(token);


                            apv.setFromStepNo(-1);

                            apv.setToStepNo(ParmVars.TOSTEPANY);
                            apv.setTokenType(_RToken.getTokenKey().GetTokenType());
                            apv.setEnabled(_RToken.isEnabled());
                            aparms.addAppValue(apv);
                        }
                        //aparms.setRow(row);
                        //row++;
                        //aparms.crtGenFormat(true);
                        newparms.add(aparms);
                    }

                }


                //respqrs = pqrs;
                //レスポンストークン解析
                String body = pqrs.response.getBodyStringWithoutHeader();

                String res_contentMimeType = pqrs.response.getContentMimeType();// Content-Type's Mimetype: ex. "text/html"

                // Content-Type/subtype matched excludeMimeType then skip below codes..
                if(!ParmVars.isMimeTypeExcluded(res_contentMimeType)){
                    //### skip start
                    //レスポンスから追跡パラメータ抽出
                    ParmGenParser pgparser = new ParmGenParser(body);
                    ArrayList<ParmGenToken> bodytklist = pgparser.getNameValues();
                    ParmGenArrayList tklist = new ParmGenArrayList();// tklist: tracking token list
                    ParmGenResTokenCollections trackurltoken = new ParmGenResTokenCollections();
                    //trackurltoken.request = pqrs.request;
                    trackurltoken.resTokenUrlDecodedNameSlashValueHash = new HashMap<>();
                    trackurltoken.resTokenUrlDecodedNameHash = new HashMap<>();
                    trackurltoken.resTokenUrlDecodedValueHash = new HashMap<>();
                    trackurltoken.resEncode = pqrs.response.getPageEnc();
                    InterfaceCollection<ParmGenToken> ic = pqrs.response.getLocationTokens(tklist);
                    //JSON parse
                    ParmGenGSONDecoder jdecoder = new ParmGenGSONDecoder(body);
                    List<ParmGenToken> jtklist = jdecoder.parseJSON2Token();

                    //add extracted tokens to tklist
                    tklist.addAll(bodytklist);
                    tklist.addAll(jtklist);

                    for (ParmGenToken token : tklist) {
                        //PHPSESSID, token, SesID, jsessionid
                        String tokenName = token.getTokenKey().getName();
                        String tokenValue = token.getTokenValue().getValue();
                        if (tokenName != null && !tokenName.isEmpty() && tokenValue != null && !tokenValue.isEmpty()) { // token must have name and value.
                            boolean namematched = false;
                            for (String tkn : tknames) {//予約語に一致
                                if (tokenName.equalsIgnoreCase(tkn)) {//完全一致 tokenname  that matched reserved token name
                                    namematched = true;
                                    break;
                                }
                            }
                            if (!namematched) {//nameはtknamesに一致しない
                                for (String tkn : tknames) {
                                    if (tokenName.toUpperCase().indexOf(tkn.toUpperCase()) != -1) {//予約語に部分一致 tokenname that partially matched reserved token name
                                        namematched = true;
                                        break;
                                    }
                                }
                            }
                            // value値がToken値だとみられる
                            if (!namematched) {//nameはtknamesに一致しない


                                if (ParmGenUtil.isTokenValue(tokenValue)) {// token value that looks like tracking token
                                    namematched = true;
                                }
                            }
                            token.setEnabled(namematched);//namematched==true: token that looks like tracking token
                            String urlDecodedTokenName = ParmGenUtil.URLdecode(tokenName, trackurltoken.resEncode.getIANACharsetName());
                            String urlDecodedTokenValue = ParmGenUtil.URLdecode(tokenValue, trackurltoken.resEncode.getIANACharsetName());
                            String nameSlashValue = urlDecodedTokenName + "/" + urlDecodedTokenValue;
                            trackurltoken.resTokenUrlDecodedNameSlashValueHash.put(nameSlashValue, token);
                            trackurltoken.resTokenUrlDecodedNameHash.put(urlDecodedTokenName, token);
                            trackurltoken.resTokenUrlDecodedValueHash.put(urlDecodedTokenValue, token);
                            trackurltoken.fromStepNo = pos;
                        }

                    }

                    if(!trackurltoken.resTokenUrlDecodedNameSlashValueHash.isEmpty()){
                        urltokens.add(trackurltoken);
                    }
                    //### skip end
                }else{
                    logger4j.debug("automacro:Response analysis skipped stepno:" + pos + " MIMEtype:" + res_contentMimeType);
                }


                pos++;
            }

            logger4j.debug("newparms.size=" + newparms.size());
            new ParmGenTokenJDialog(pmtProvider, false, newparms, pmt).setVisible(true);
        }
    }//GEN-LAST:event_ParamTrackingActionPerformed

    private void ClearMacroActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ClearMacroActionPerformed
        // TODO add your handling code here:
        clear();
    }//GEN-LAST:event_ClearMacroActionPerformed

    private void LoadActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_LoadActionPerformed
        // TODO add your handling code here:
        loadProject();
    }//GEN-LAST:event_LoadActionPerformed

    private void RepeaterActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RepeaterActionPerformed
        // TODO add your handling code here:
        int tabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (pos != -1) {
                ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
                pmt.setCurrentRequest(pos);
                pmt.sendToRepeater(pos, tabIndex);
            }
            Redraw();
        }
    }//GEN-LAST:event_RepeaterActionPerformed

    private void ScannerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ScannerActionPerformed
        // TODO add your handling code here:
    	int tabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (pos != -1) {
                ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
                pmt.setCurrentRequest(pos);
                pmt.sendToScanner(pos, tabIndex);

            }
            Redraw();
        }
    }//GEN-LAST:event_ScannerActionPerformed

    private void IntruderActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_IntruderActionPerformed
        // TODO add your handling code here:
    	int tabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (pos != -1) {
                ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
                pmt.setCurrentRequest(pos);
                pmt.sendToIntruder(pos, tabIndex);

            }
            Redraw();
        }
    }//GEN-LAST:event_IntruderActionPerformed

    private void SaveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SaveActionPerformed
        // TODO add your handling code here:
        
        
        File cfile = new File(ParmVars.getParmFile());
        String dirname = cfile.getParent();
        JFileChooser jfc = new JFileChooser(dirname);
        jfc.setSelectedFile(cfile);
        ParmFileFilter pFilter=new ParmFileFilter();
        jfc.setFileFilter(pFilter);
        if(jfc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            //code to handle choosed file here.
            File file = jfc.getSelectedFile();
            String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");
            if(!pFilter.accept(file)){//拡張子無しの場合は付与
                name += ".json";
            }
            // boolean filenamechanged = false;
            // if(ParmVars.getParmFile()==null||!ParmVars.getParmFile().equals(name)){
            //    filenamechanged = true;
            // }
            ParmVars.setParmFile(name);

            /**
            ParmGenMacroTrace pmt = getSelectedParmGenMacroTrace();
            if (pmt != null) {
                ParmGenGSONSave csv = new ParmGenGSONSave(null, pmt);
                csv.GSONsave();
            }
             **/
            ParmGenGSONSaveV2 gson = new ParmGenGSONSaveV2(pmtProvider);
            gson.GSONsave();
            updateSelectedTabIndex();
        }
    }//GEN-LAST:event_SaveActionPerformed

    private void editActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editActionPerformed
        // TODO add your handling code here:
        String reg = "";
        //String orig = MacroRequest.getText();
        
    
        int tabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList == null) return;
    	int pos = requestJList.getSelectedIndex();
        if(pos<0)return;
        
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(tabIndex);
        if(pmt!=null){
            PRequestResponse pqr = pmt.getRequestResponseCurrentList(pos);
            if (pqr != null) {
                StyledDocumentWithChunk chunkdoc = this.getMacroRequestStyledDocument();
                if (chunkdoc != null) {
                    StyledDocumentWithChunk newchunkdoc = new StyledDocumentWithChunk(chunkdoc); // newchunkdoc is newly created and independent from chunkdoc.
                    new ParmGenRegex(this, reg, newchunkdoc).setVisible(true);
                }
            }
        }
      
        
    }//GEN-LAST:event_editActionPerformed

    private void showActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_showActionPerformed
        // TODO add your handling code here:
        String reg = "";
        int tabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            String orig = MacroResponse.getText();
            if (pos != -1) {
                StyledDocument doc = MacroResponse.getStyledDocument();
                new ParmGenRegex(this,reg,doc).setVisible(true);
            }
        }
        
    }//GEN-LAST:event_showActionPerformed

    private void StartScanActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_StartScanActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_StartScanActionPerformed

    private void MBmonitorofprocessingActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_MBmonitorofprocessingActionPerformed
        // TODO add your handling code here:

    }//GEN-LAST:event_MBmonitorofprocessingActionPerformed

    private void MBfromStepNoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_MBfromStepNoActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_MBfromStepNoActionPerformed

    private void TrackModeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_TrackModeActionPerformed
        // TODO add your handling code here:
        pmtProvider.setCBreplaceTrackingParam(isReplaceMode());

    }//GEN-LAST:event_TrackModeActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        try {
            // TODO add your handling code here:
            java.awt.Desktop.getDesktop().browse(new URI(bundle.getString("MacroBuilderUI.baselinemode.text")));
        } catch (IOException ex) {
            Logger.getLogger(MacroBuilderUI.class.getName()).log(Level.SEVERE, null, ex);
        } catch (URISyntaxException ex) {
            Logger.getLogger(MacroBuilderUI.class.getName()).log(Level.SEVERE, null, ex);
        }
    
    
     
    }//GEN-LAST:event_jButton1ActionPerformed

    private void messageViewStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_messageViewStateChanged
        // TODO add your handling code here:
        // jTabbedPane tab select problem fixed. by this eventhandler is defined... what a strange behavior. 
        //int selIndex = messageView.getSelectedIndex();
	//String t = messageView.getTitleAt(selIndex);
	//logger4j.info("messageViewStateChanged: title[" + t + "]");
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        messageViewTabbedPaneSelectedContentsLoad(selectedTabIndex);
    }//GEN-LAST:event_messageViewStateChanged

    private void UpSelectedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_UpSelectedActionPerformed
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        int pos = requestJList.getSelectedIndex();
        if ( pos > 0 ) {
            ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
            List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
            // rlist,  RequestList
            logger4j.debug("selected:" + pos);
            // exchange pos and pos-1
            PRequestResponse upobj = prequestResponseList.get(pos);
            PRequestResponse downobj = prequestResponseList.get(pos-1);
            prequestResponseList.set(pos-1, upobj);
            prequestResponseList.set(pos, downobj);
            List<PRequestResponse> originalPRR = pmt.getOriginalPRequestResponseList();
            upobj = originalPRR.get(pos);
            downobj = originalPRR.get(pos-1);
            originalPRR.set(pos-1, upobj);
            originalPRR.set(pos, downobj);

            String upelem = String.format("%03d",pos-1) + '|' + upobj.request.getURL();
            String downelem = String.format("%03d",pos) + '|' + downobj.request.getURL();

            DefaultListModel<String> requestJListModel = (DefaultListModel<String>)requestJList.getModel();
            requestJListModel.set(pos-1, upelem);
            requestJListModel.set(pos, downelem);
            pmt.exchangeStepNo(pos-1, pos);

            if (ParmVars.isSaved()) { // if you have been saved params. then overwrite.
                /**
                ParmGenGSONSave csv = new ParmGenGSONSave(null, pmt);
                csv.GSONsave();
                 **/
                ParmGenGSONSaveV2 gson = new ParmGenGSONSaveV2(pmtProvider);
                gson.GSONsave();
            }

            requestJList.setSelectedIndex(pos-1);
        }
        
    }//GEN-LAST:event_UpSelectedActionPerformed

    private void DownSelectedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DownSelectedActionPerformed
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
        if (pmt == null) return;
        List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
        int pos = requestJList.getSelectedIndex();
        int siz = prequestResponseList != null ? prequestResponseList.size() : 0;
        if ( pos > -1 && pos < siz - 1 ) {
            
            // rlist,  RequestList
            logger4j.debug("selected:" + pos);
            // exchange pos and pos-1
            PRequestResponse upobj = prequestResponseList.get(pos+1);
            PRequestResponse downobj = prequestResponseList.get(pos);
            prequestResponseList.set(pos, upobj);
            prequestResponseList.set(pos+1, downobj);
            List<PRequestResponse> originalPRR = pmt.getOriginalPRequestResponseList();
            upobj = originalPRR.get(pos+1);
            downobj = originalPRR.get(pos);
            originalPRR.set(pos, upobj);
            originalPRR.set(pos+1, downobj);

            String upelem = String.format("%03d",pos) + '|' + upobj.request.getURL();
            String downelem = String.format("%03d",pos+1) + '|' + downobj.request.getURL();

            DefaultListModel<String> requestJListModel = (DefaultListModel<String>) requestJList.getModel();
            requestJListModel.set(pos, upelem);
            requestJListModel.set(pos+1, downelem);
            pmt.exchangeStepNo(pos, pos+1);

            if (ParmVars.isSaved()) { // if you have been saved params. then overwrite.
                /**
                ParmGenGSONSave csv = new ParmGenGSONSave(null, pmt);
                csv.GSONsave();
                 **/
                ParmGenGSONSaveV2 gson = new ParmGenGSONSaveV2(pmtProvider);
                gson.GSONsave();
            }

            requestJList.setSelectedIndex(pos+1);
        }
    }//GEN-LAST:event_DownSelectedActionPerformed

    private void deleteRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteRequestActionPerformed
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        int pos = requestJList.getSelectedIndex();
        if ( pos != -1 ) {
            ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
            List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
            List<AppParmsIni> hasposlist = pmt.getAppParmIniHasStepNoSpecified(pos);
            if ( !hasposlist.isEmpty()) {
                PRequestResponse pqrs = prequestResponseList.get(pos);
                String m = String.format(
                        java.text.MessageFormat.format(
                                bundle.getString("MacroBuilderUI.deleteRequestAction.text"),
                                new Object[] {pqrs.request.getURL()}));
                int rv = JOptionPane.showConfirmDialog(
                        this, m, bundle.getString("MacroBuilderUI.deleteConfirm.text"), JOptionPane.YES_NO_OPTION);
                if (rv != JOptionPane.YES_OPTION) {
                    return;
                }
            }
            prequestResponseList.remove(pos);
            DefaultListModel<String> requestJListModel = (DefaultListModel<String>) requestJList.getModel();
            requestJListModel.remove(pos);
            List<PRequestResponse> originalPRR = pmt.getOriginalPRequestResponseList();
            originalPRR.remove(pos);

            for(int i = pos; i < requestJListModel.size(); i++) {
                PRequestResponse pqrs = prequestResponseList.get(i);
                String elem = String.format("%03d",i) + '|' + pqrs.request.getURL();
                requestJListModel.set(i, elem);
            }
            int siz = prequestResponseList.size();
            if ( pos == siz - 1 && siz > 1) {
                int npos = pos - 1;
                requestJList.setSelectedIndex(npos);
            }
            
            
            hasposlist.stream().forEach(pini -> {
                int trackfromstep = pini.getTrackFromStep();
                if ( trackfromstep == pos) {
                    pini.setTrackFromStep(-1); // any stepno
                } else if ( trackfromstep > pos ) {
                    pini.setTrackFromStep(trackfromstep-1);
                }
                int settostep = pini.getSetToStep();
                if ( settostep == pos) {
                    pini.setSetToStep(ParmVars.TOSTEPANY); // any stepno
                } else if ( settostep > pos && settostep != ParmVars.TOSTEPANY) {
                    pini.setSetToStep(settostep-1);
                }
            });
            if (ParmVars.isSaved()) {
                /**
                ParmGenGSONSave csv = new ParmGenGSONSave(null, pmt);
                csv.GSONsave();
                 **/
                ParmGenGSONSaveV2 gson = new ParmGenGSONSaveV2(pmtProvider);
                gson.GSONsave();
            } else if (pmt != null) {
                pmt.nullfetchResValAndCookieMan();
            }
            
        }
    }//GEN-LAST:event_deleteRequestActionPerformed

    private void MacroRequestMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_MacroRequestMouseClicked
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {// popup menu trigger occured.
            logger4j.debug("MacroRequestMouseClicked PopupTriggered.");
            RequestEdit.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_MacroRequestMouseClicked

    private void MacroRequestMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_MacroRequestMousePressed
        // TODO add your handling code here:
        logger4j.debug("MacroRequestMousePressed...start");
        messageViewTabbedPaneSelectedContentsLoad(MacroRequestListTabsCurrentIndex); // must content load before RequestEdit.show
        if (evt.isPopupTrigger()) {
            logger4j.debug("MacroRequestMousePressed PopupTriggered.");
            RequestEdit.show(evt.getComponent(), evt.getX(), evt.getY());
        }
        logger4j.debug("MacroRequestMousePressed...end");
    }//GEN-LAST:event_MacroRequestMousePressed

    private void MacroRequestMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_MacroRequestMouseReleased
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {// popup menu trigger occured. 
            logger4j.debug("MacroRequestMouseReleased PopupTriggered.");
            RequestEdit.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_MacroRequestMouseReleased

    private void MacroResponseMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_MacroResponseMouseClicked
        // TODO add your handling code here:
        logger4j.debug("MacroResponseMouseClicked start");
        if (evt.isPopupTrigger()) {// popup menu trigger occured.
            logger4j.debug("MacroResponseMouseClicked PoupupTriggered.");
            ResponseShow.show(evt.getComponent(), evt.getX(), evt.getY());
        }
        logger4j.debug("MacroResponseMouseClicked end");
    }//GEN-LAST:event_MacroResponseMouseClicked

    private void MacroResponseMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_MacroResponseMousePressed
        // TODO add your handling code here:
        logger4j.debug( "MacroResponseMousePressed...start");
        messageViewTabbedPaneSelectedContentsLoad(MacroRequestListTabsCurrentIndex); // must content load before ResponseShow.show
        if (evt.isPopupTrigger()) {
            logger4j.debug("MacroResponseMousePressed PopupTriggered.");
            ResponseShow.show(evt.getComponent(), evt.getX(), evt.getY());
        }
        logger4j.debug("MacroResponseMousePressed...end");
    }//GEN-LAST:event_MacroResponseMousePressed

    private void MacroResponseMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_MacroResponseMouseReleased
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {// popup menu trigger occured. 
            logger4j.debug("MacroResponseMouseReleased PopupTriggered.");
            ResponseShow.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_MacroResponseMouseReleased

    private void restoreActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_restoreActionPerformed
        /**
         * update current PRequestResponse(clone PRequestResponse from originalrlist to rlist)
         */
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
        if (pmt == null) return;
        List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        int idx = requestJList.getSelectedIndex();
        if (idx > -1 && prequestResponseList != null && idx < prequestResponseList.size()) {
            PRequestResponse prr = pmt.getOriginalRequest(idx);// get original PRequestResponse in originalrlist
            if (prr != null) {
                PRequestResponse current = pmt.getRequestResponseCurrentList(idx);
                current.updateRequestResponse(prr.request.clone(), prr.response.clone());// clone original PRequestResponse to CurrentList(rlist)
                ParmGenTextDoc reqdoc = new ParmGenTextDoc(MacroRequest);
                reqdoc.setRequestChunks(prr.request);
                ParmGenTextDoc resdoc = new ParmGenTextDoc(MacroResponse);
                resdoc.setResponseChunks(prr.response);
                if (pmt != null) {
                    pmt.nullfetchResValAndCookieMan();
                }
            }
        }
    }//GEN-LAST:event_restoreActionPerformed

    private void updateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_updateActionPerformed
        /**
         * update Original PRequestResponse with current selected(displayed) PRequestResponse
         */
        // TODO add your handling code here:
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
        if (pmt == null) return;
        List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        int idx = requestJList.getSelectedIndex();
        if (idx > -1 && prequestResponseList != null && idx < prequestResponseList.size()) {
            PRequestResponse current = pmt.getRequestResponseCurrentList(idx);
            StyledDocumentWithChunk doc = this.getMacroRequestStyledDocument();
            if (doc != null) {
                PRequest newrequest = doc.reBuildPRequestFromDocTextAndChunks(); // request newly created from DocText and Chunks
                current.request = newrequest;

                PRequestResponse original = pmt.getOriginalRequest(idx);
                original.updateRequestResponse(current.request, current.response);// copy current PRequestResponse to original list(originalrlist)
                if (ParmVars.isSaved()) { // if you have been saved params. then overwrite.
                    /**
                    ParmGenGSONSave csv = new ParmGenGSONSave(null, pmt);
                    csv.GSONsave();
                     **/
                    ParmGenGSONSaveV2 gson = new ParmGenGSONSaveV2(pmtProvider);
                    gson.GSONsave();
                } else {
                    pmt.nullfetchResValAndCookieMan();
                }
            }
        }
    }//GEN-LAST:event_updateActionPerformed

    private void jCheckBox1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBox1ActionPerformed
        /**
         * scan all requests from current request to FinalResponse or until subsequence scan limit.
         */
        // TODO add your handling code here:
    }//GEN-LAST:event_jCheckBox1ActionPerformed

    private void subSequenceScanLimitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_subSequenceScanLimitActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_subSequenceScanLimitActionPerformed

    private void MacroRequestListTabsStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_MacroRequestListTabsStateChanged
        // TODO add your handling code here:
        logger4j.debug("Enter stateChanged");
        updateSelectedTabIndex();
        setCloseButtonStates();
        int indexOfPlusBtnPanel = MacroRequestListTabs.indexOfComponent(plusBtnPanel);
        logger4j.debug("indexOfPlusBtnPanel=" + indexOfPlusBtnPanel);
        if (MacroRequestListTabsCurrentIndex != -1 && indexOfPlusBtnPanel != -1) {
            if (MacroRequestListTabsCurrentIndex == indexOfPlusBtnPanel) {
                logger4j.debug("Enter setSelectedIndex(" + (indexOfPlusBtnPanel - 1) + ")");
                MacroRequestListTabs.setSelectedIndex(indexOfPlusBtnPanel - 1);
                logger4j.debug("Leave setSelectedIndex(" + (indexOfPlusBtnPanel - 1) + ")");
                if (this.maxTabIndex < indexOfPlusBtnPanel) {
                    // start the event of clicked plusBtnPanel icon
                    logger4j.debug("plusBtnPanel icon clicked. create new tab.");
                    this.maxTabIndex++;
                    addNewRequestsToTabsPaneAtMaxTabIndex(null, this.maxTabIndex);
                    // end the event of clicked plusBtnPanel icon
                }
            } else {
                logger4j.debug("MacroRequestListTabsCurrentIndex["
                        + MacroRequestListTabsCurrentIndex
                        + "] " + (MacroRequestListTabsCurrentIndex==indexOfPlusBtnPanel?"==":"!=") + " indexOfPlusBtnPanel[" + indexOfPlusBtnPanel + "]");
                logger4j.debug("maxTabIndex[" + this.maxTabIndex + "] " + (this.maxTabIndex<indexOfPlusBtnPanel?"<":">=") + " indexOfPlusBtnPanel[" + indexOfPlusBtnPanel + "]");
                updateCurrentSelectedRequestListDisplayContents();
            }
        }
        logger4j.debug("Leave stateChanged");
    }//GEN-LAST:event_MacroRequestListTabsStateChanged


    
    public StyledDocumentWithChunk getMacroRequestStyledDocument() {
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList != null) {
            int pos = requestJList.getSelectedIndex();
            if (displayInfo == null || pos < 0 || pos != displayInfo.selected_request_idx) {
                logger4j.error(
                        "getMacroRequestStyledDocument pos["
                                + pos
                                + "]!=selected_request_idx["
                                + displayInfo.selected_request_idx + "]");
                return null;
            }
            MacroRequestLoadContents(selectedTabIndex);
            StyledDocument doc =  MacroRequest.getStyledDocument();
            if ( doc instanceof StyledDocumentWithChunk) {
                return CastUtils.castToType(doc);
            }
        }
        return null;
    }
    
    public String getMacroRequest() {
        return MacroRequest.getText();
    }

    /**
     * update current PRequestResponse with Edited(displayed) PRequestResponse
     *
     * @param doc
     */
    @Override
    public void ParmGenRegexSaveAction(StyledDocumentWithChunk doc) {
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        ParmGenMacroTrace pmt = getParmGenMacroTraceAtTabIndex(selectedTabIndex);
        if (pmt == null) return;
        List<PRequestResponse> prequestResponseList = pmt.getPRequestResponseList();
        JList<String> requestJList = getRequestJListAtTabIndex(selectedTabIndex);
        if (requestJList == null) return;
        int idx = requestJList.getSelectedIndex();
        if(prequestResponseList != null && idx > -1 &&  idx < prequestResponseList.size()){
            try {
                PRequest newrequest = doc.reBuildPRequestFromDocTextAndChunks();// get edited request
                if (newrequest != null) {
                    pmt.updateRequestCurrentList(idx, newrequest);// copy edited request to current request
                    ParmGenTextDoc ndoc = new ParmGenTextDoc(MacroRequest);
                    ndoc.setRequestChunks(newrequest);
                    pmt.nullfetchResValAndCookieMan();
                }
            } catch (Exception ex) {
                Logger.getLogger(MacroBuilderUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    @Override
    public void ParmGenRegexCancelAction(boolean isLabelSaveBtn) {

    }

    @Override
    public String getParmGenRegexSaveBtnText(boolean isLabelSaveBtn) {
        if(!isLabelSaveBtn){
            return "Close";
        }
        return "Save";
    }

    @Override
    public String getParmGenRegexCancelBtnText(boolean isLabelSaveBtn) {
        if(!isLabelSaveBtn){
            return "Close";
        }
        return "Cancel";
    }
    
    /**
     * get subSequenceScanLimit value.
     *
     * @return 
     */
    public int getSubSequenceScanLimit() {
        String v = subSequenceScanLimit.getText();
        int subSequenceScanLimitValue = Integer.parseInt(v);
        return subSequenceScanLimitValue;
    }

    /**
     * integer input verifier for JTextField.
     */
    static class IntegerInputVerifier extends InputVerifier {
        @Override public boolean verify(JComponent c) {
          boolean verified = false;
          if (c instanceof JTextComponent) {
            JTextComponent textField = (JTextComponent) c;
            try {
              Integer.parseInt(textField.getText());
              verified = true;
            } catch (NumberFormatException ex) {
              UIManager.getLookAndFeel().provideErrorFeedback(c);
            }
            if (!verified) {
                JOptionPane.showMessageDialog(c,"subsequence scan limit\nPlease input numeric only.");
            }
          }
          return verified;
        }
    }

    /**
     * get selected tab index of Macro Request List Tabs
     * @return >= 0: selected index ==-1: no selection
     */
    public int getSelectedTabIndexOfMacroRequestList() {
        return MacroRequestListTabs.getSelectedIndex();
    }

    /**
     * get request list of selected tab
     *
     * @return 
     */
    private JList<String> getSelectedRequestJList() {
        int selectedTabIndex = getSelectedTabIndexOfMacroRequestList();
        try {
            return getRequestJListAtTabIndex(selectedTabIndex);
        } catch (IndexOutOfBoundsException e) {
            
        }
        return null;
    }
    
    public JList<String> getRequestJListAtTabIndex(int tabIndex) throws IndexOutOfBoundsException {
        JList<String> requestJList = requestJLists.get(tabIndex);
        return requestJList;
    }
    
    /**
     * Gets the selectedIndex of the RequestJList that is exist in the specified tab
     *
     * @param tabIndex
     * @return >=0: selected index ==-1: no selected
     */
    public int getRequestJListSelectedIndexAtTabIndex(int tabIndex) {
        int pos = -1;
        try {
            JList<String> requestJList = getRequestJListAtTabIndex(tabIndex);
            pos = requestJList.getSelectedIndex();
        } catch (IndexOutOfBoundsException e) {
        }
        return pos;
    }

    /**
     * Load Project file.
     *
     * @return true - succeeded, false - load failed.
     */
    public boolean loadProject() {
        // TODO add your handling code here:
        File cfile = new File(ParmVars.getParmFile());
        String dirname = cfile.getParent();
        JFileChooser jfc = new JFileChooser(dirname);
        jfc.setSelectedFile(cfile);
        ParmFileFilter pFilter=new ParmFileFilter();
        jfc.setFileFilter(pFilter);
        if(jfc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            //code to handle choosed file here.
            File file = jfc.getSelectedFile();
            String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");

            return loadProjectFromFile(name);
        }
        return false;
    }

    /**
     * load project from specified filename.
     *
     * @param filename project file name
     * @return true - success false - failed
     */
    public boolean loadProjectFromFile(String filename) {
        if(checkAndLoadFile(filename)){
            //load succeeded..
            updateSelectedTabIndex();
            return true;
        }
        return false;
    }

    private boolean checkAndLoadFile(String filename) {
        //
        boolean noerror = false;
        List<Exception> exlist = new ArrayList<>(); // Exception list
        logger4j.info("checkAndLoadFile called.");

        ArrayList<AppParmsIni> rlist = null;
        String pfile = filename;

        try {

            String rdata;
            String jsondata = new String("");
            FileReader fr = new FileReader(pfile);
            try {

                BufferedReader br = new BufferedReader(fr);
                while ((rdata = br.readLine()) != null) {
                    jsondata += rdata;
                } // end of while((rdata = br.readLine()) != null)
                fr.close();
                fr = null;
            } catch (Exception e) {
                logger4j.error("File Open/RW error", e);
                exlist.add(e);
            } finally {
                if (fr != null) {
                    try {
                        fr.close();
                        fr = null;
                    } catch (Exception e) {
                        fr = null;
                        logger4j.error("File Close error", e);
                        exlist.add(e);
                    }
                }
            }

            if (exlist.size() > 0) return noerror;

            GsonParser parser = new GsonParser();

            ParmGenGSON gjson = new ParmGenGSON();
            JsonElement element = com.google.gson.JsonParser.parseString(jsondata);

            if (parser.elementLoopParser(element, gjson)) {
                rlist = gjson.Getrlist();
                List<PRequestResponse> requestList = gjson.GetMacroRequests();
                List<ParmGenGSON.AppParmAndSequence> appParmAndSequenceList = gjson.getAppParmAndSequenceList();
                if (appParmAndSequenceList != null
                    && appParmAndSequenceList.size() > 0) { // v2 format JSON file
                    clear();
                    ParmVars.parmfile = filename;
                    ParmVars.Version = gjson.getVersion();
                    ParmVars.setExcludeMimeTypes(gjson.getExcludeMimeTypes());
                    appParmAndSequenceList.forEach(
                            pRequestResponseSequence -> {
                                addNewRequestsToTabsPaneAtMaxTabIndex(pRequestResponseSequence, this.maxTabIndex);
                                this.maxTabIndex++;
                            }
                    );
                    if (this.maxTabIndex > 0) {
                        this.maxTabIndex--;
                    }
                    noerror = true;
                    Redraw();
                    ParmVars.Saved(true);
                } else if (requestList != null && requestList.size() > 0) { // v1 format JSON file
                    clear();
                    ParmGenMacroTrace pmt = addNewRequests(requestList);
                    if (pmt != null) {
                        int creq = gjson.getCurrentRequest();
                        pmt.setCurrentRequest(creq);
                        ParmVars.parmfile = filename;
                        ParmVars.Version = gjson.getVersion();
                        Encode firstRequestEncode = requestList.get(0).request.getPageEnc();
                        pmt.setSequenceEncode(firstRequestEncode);
                        ParmVars.setExcludeMimeTypes(gjson.getExcludeMimeTypes());
                        pmt.updateAppParmsIniAndClearCache(rlist);
                        noerror = true;
                        Redraw();
                        ParmVars.Saved(true);
                    } else {
                        logger4j.error("pmt is null");
                    }
                } else {
                    logger4j.error("requestList size is zero");
                }
            }
        } catch (Exception e) { // JSON file load failed.
            logger4j.error("Parse error", e);
            exlist.add(e);
        }

        logger4j.info("--------- JSON load END ----------");
        return noerror;
    }

    static class DisplayInfoOfRequestListTab {
        public int selected_request_idx = -1;
        public boolean isLoadedMacroCommentContents = false;
        public boolean isLoadedMacroRequestContents = false;
        public boolean isLoadedMacroResponseContents = false;
        
        DisplayInfoOfRequestListTab() {
            clear();
        }

        public void clear() {
            selected_request_idx = -1;
            clearViewFlags();
        }

        public void clearViewFlags() {
            isLoadedMacroCommentContents = false;
            isLoadedMacroRequestContents = false;
            isLoadedMacroResponseContents = false;
        }
    }

    /**
     * get MacroRequest Tab Title String
     * @param tabIndex
     * @return
     */
    public String getMacroRequestTabTitleAt(int tabIndex) {
        return MacroRequestListTabs.getTitleAt(tabIndex);
    }

    /**
     * get MacroRequest's tab count except "+"(addNewTab) button tab.
     * @return int
     */
    public int getMacroRequestTabCount() {
        return MacroRequestListTabs.getTabCount() - 1;
    }

    public ParmGenMacroTraceProvider getParmGenMacroTraceProvider() {
        return this.pmtProvider;
    }

    private void updateSelectedTabIndex() {
        int selectedTabIndex = MacroRequestListTabs.getSelectedIndex();
        if (selectedTabIndex != -1) MacroRequestListTabsCurrentIndex = selectedTabIndex;

        logger4j.debug("selectedindex:" + selectedTabIndex + " MacroRequestListTabsCurrentIndex:" + MacroRequestListTabsCurrentIndex);
    }

    /**
     * Button for adding new Tab to RequestList(jTabbedPane).
     */
    private void addPlusTabButtonToRequestList() {
        // Button for adding new Tab to JTabbedPane.
        plusBtnPanel = new JPanel();
        MacroRequestListTabs.addTab("", PLUS_BUTTON_ICON, plusBtnPanel, ParmVars.getZapResourceString("MacroBuilderUI.addNewTabToolTip.text"));
        // MacroRequestListTabs.addTab("", PLUS_BUTTON_ICON, plusBtnPanel);
    }

    /**
     * create Close "X" button for Tab in TabbedPane
     * @param tabTitle
     * @param maxTabIndex
     * @return
     */
    private JPanel createCloseXbtnForTabbedPane(String tabTitle, int maxTabIndex) {
        CloseXbtnTabPanel tabPanel = new CloseXbtnTabPanel(tabTitle,
                new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        logger4j.debug("Enter closeXbtnActionPerfomed");
                        closeXbtnActionPerfomed();
                        logger4j.debug("Leave closeXbtnActionPerfomed");
                    }
                });
        MacroRequestListTabs.setTabComponentAt(maxTabIndex, tabPanel);
        return tabPanel;
    }

    private void closeXbtnActionPerfomed() {
        int currentSelectedTabIndex = MacroRequestListTabs.getSelectedIndex();
        if (currentSelectedTabIndex > 0 && currentSelectedTabIndex <= maxTabIndex) {
            pmtProvider.removeBaseInstance(currentSelectedTabIndex);
            requestJLists.remove(currentSelectedTabIndex);
            logger4j.debug("Begin MacroRequestListTabs.remove");
            MacroRequestListTabs.remove(currentSelectedTabIndex);
            logger4j.debug("End MacroRequestListTabs.remove");
            maxTabIndex--;
            logger4j.debug("currentIndex deleted: " + currentSelectedTabIndex + " maxTabIndex: " + maxTabIndex);
        }
    }

    private void setCloseButtonStates() {
        // Hide all 'close' buttons except for the selected tab
        for (int i = 0; i < MacroRequestListTabs.getTabCount(); i++) {
            Component tabCom = MacroRequestListTabs.getTabComponentAt(i);
            if (tabCom != null && tabCom instanceof CloseXbtnTabPanel) {
                CloseXbtnTabPanel jp = (CloseXbtnTabPanel) tabCom;
                jp.setEnableCloseButton(i == MacroRequestListTabs.getSelectedIndex());
                logger4j.debug("setCloseButtonState i:" + i + (i== MacroRequestListTabs.getSelectedIndex() ? " Enable" : " Disable"));
            }
        }
    }

    private void MacroCommentsMouseClicked(java.awt.event.MouseEvent evt) {
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {

        }
        if ((evt.getModifiersEx() & InputEvent.BUTTON1_DOWN_MASK) != 0) { // left button clicked

        }
    }

    private void MacroCommentsMousePressed(java.awt.event.MouseEvent evt) {
        // TODO add your handling code here:
        messageViewTabbedPaneSelectedContentsLoad(MacroRequestListTabsCurrentIndex); // at this point, must load contents because first called MousePressed Event than any other mouse events
        if (evt.isPopupTrigger()) {

        }
        if ((evt.getModifiersEx() & InputEvent.BUTTON1_DOWN_MASK) != 0) { // left button clicked

        }
    }

    private void MacroCommentsMouseReleased(java.awt.event.MouseEvent evt) {
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {

        }
        if ((evt.getModifiersEx() & InputEvent.BUTTON1_DOWN_MASK) != 0) { // left button clicked

        }
    }

    public void clearDisplayInfoViewFlags() {
        displayInfo.clearViewFlags();
    }

    public JPanel getMessageViewPanel() {
        return this.messageViewPanel;
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox CBinheritFromCache;
    private javax.swing.JButton ClearMacro;
    private javax.swing.JButton DownSelected;
    private javax.swing.JCheckBox FinalResponse;
    private javax.swing.JMenuItem Intruder;
    private javax.swing.JButton Load;
    private javax.swing.JCheckBox MBfromStepNo;
    private javax.swing.JCheckBox MBmonitorofprocessing;
    private javax.swing.JCheckBox MBtoStepNo;
    private javax.swing.JTextArea MacroComments;
    private javax.swing.JTextPane MacroRequest;
    private javax.swing.JTabbedPane MacroRequestListTabs;
    private javax.swing.JTextPane MacroResponse;
    private javax.swing.JButton ParamTracking;
    private javax.swing.JPopupMenu PopupMenuForRequestList;
    private javax.swing.JMenuItem Repeater;
    private javax.swing.JPopupMenu RequestEdit;
    private javax.swing.JList<String> RequestList;
    private javax.swing.JPopupMenu ResponseShow;
    private javax.swing.JButton Save;
    private javax.swing.JMenuItem Scanner;
    private javax.swing.JMenu SendTo;
    private javax.swing.JButton StartScan;
    private javax.swing.JComboBox<String> TrackMode;
    private javax.swing.JButton UpSelected;
    private javax.swing.JButton custom;
    private javax.swing.JMenuItem deleteRequest;
    private javax.swing.JMenuItem showRequest;
    private javax.swing.JMenuItem disableRequest;
    private javax.swing.JMenuItem edit;
    private javax.swing.JMenuItem enableRequest;
    private javax.swing.JButton jButton1;
    private javax.swing.JCheckBox jCheckBox1;
    private javax.swing.JCheckBox jCheckBox2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPanel requestView;
    private javax.swing.JPanel responseView;
    private javax.swing.JPanel trackingView;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane requestScroller;
    private javax.swing.JScrollPane trackingScroller;
    private javax.swing.JScrollPane responseScroller;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JTabbedPane messageView;
    private javax.swing.JPanel messageViewPanel;
    private javax.swing.JPanel descriptionVacantArea;
    private javax.swing.JLabel dummyLabel;
    private javax.swing.JLabel requestListNum;
    private javax.swing.JMenuItem restore;
    private javax.swing.JMenuItem show;
    private javax.swing.JTextField subSequenceScanLimit;
    private javax.swing.JMenuItem update;
    private javax.swing.JTextField waitsec;
    // End of variables declaration//GEN-END:variables


}