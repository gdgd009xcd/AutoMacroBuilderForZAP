/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.awt.event.InputEvent;
import java.io.File;
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
import javax.swing.text.StyledDocument;

import org.zaproxy.zap.extension.automacrobuilder.*;


/**
 *
 * @author gdgd009xcd
 */
@SuppressWarnings("serial")
public class MacroBuilderUI  extends javax.swing.JPanel implements  InterfaceParmGenRegexSaveCancelAction {

    
    private static org.apache.logging.log4j.Logger logger4j = org.apache.logging.log4j.LogManager.getLogger();
    
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    List<PRequestResponse> rlist = null;
    ParmGenMacroTrace pmt = null;

    int EditTarget = -1;
    DefaultListModel<String> RequestListModel = null;
    Encode EditPageEnc = Encode.ISO_8859_1;
    static final int REQUEST_DISPMAXSIZ = 500000;//1MB
    static final int RESPONSE_DISPMAXSIZ = 1000000;//1MB
    
    private int selected_request_idx = -1;
    private boolean isLoadedMacroRequestContents = false;
    private boolean isLoadedMacroResponseContents = false;
    private boolean isLoadedMacroCommentContents = false;
    
    /**
     * Creates new form MacroBuilderUI
     */
    @SuppressWarnings("unchecked")
    public MacroBuilderUI(ParmGenMacroTrace _pmt) {
        pmt = _pmt;
        initComponents();
        RequestList.setCellRenderer((ListCellRenderer<Object>)new MacroBuilderUIRequestListRender(this));
        RequestListModel = new DefaultListModel<>();
        RequestListModel.clear();
        RequestList.setModel(RequestListModel);

        pmt.setUI(this);


        pmt.setMBreplaceCookie(true);
        pmt.setCBInheritFromCache(CBinheritFromCache.isSelected());
        pmt.setMBFinalResponse(FinalResponse.isSelected());
        pmt.setMBResetToOriginal(true);
        pmt.setMBmonitorofprocessing(MBmonitorofprocessing.isSelected());
        
        pmt.setMBreplaceTrackingParam(isReplaceMode());
        
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
    
    public ParmGenMacroTrace getParmGenMacroTrace() {
        return pmt;
    }

    @SuppressWarnings("unchecked")
    public void clear() {
        selected_request_idx = -1;
        isLoadedMacroRequestContents = false;
        isLoadedMacroResponseContents = false;
        isLoadedMacroCommentContents = false;
        //JListをクリアするには、modelのremove & jListへModelセットが必須。
        RequestListModel.removeAllElements();
        RequestList.setModel(RequestListModel);
        MacroRequest.setText("");
        MacroResponse.setText("");
        MacroComments.setText("");
        rlist = null;
        if (pmt != null) {
            pmt.clear();
        }
    }

    @SuppressWarnings("unchecked")
    public void addNewRequests(List<PRequestResponse> _rlist) {
        AppParmsIni pini;
        if (_rlist != null) {
            if(rlist==null){
                rlist = _rlist;
            }else{
                rlist.addAll(_rlist);
            }
            if (pmt != null) {
                pmt.setRecords(_rlist);
            }
            Iterator<PRequestResponse> it = rlist.iterator();
            int ii = 0;

            RequestListModel.removeAllElements();
            while (it.hasNext()) {

                //model.addRow(new Object[] {false, pini.url, pini.getIniValDsp(), pini.getLenDsp(), pini.getTypeValDsp(),pini.getAppValuesDsp(),pini.getCurrentValue()});
                PRequestResponse pqr = it.next();
                String url = pqr.request.getURL();
                RequestListModel.addElement((String.format("%03d",ii++) + '|' + url));
            }
            RequestList.setModel(RequestListModel);
        }

    }

    /**
     * update GUI contents with Current Selected request
     *
     */
    public void updateCurrentSelectedRequestListDisplayContents() {
        int cpos = RequestList.getSelectedIndex();
        if (cpos != -1) { // current cpos request is displayed in MacroRequest.
            selected_request_idx = cpos;
            isLoadedMacroCommentContents = false;
            isLoadedMacroRequestContents = false;
            isLoadedMacroResponseContents = false;

            paramlogTabbedPaneSelectedContentsLoad();
        }
    }

    public void Redraw() {
        //ListModel cmodel = RequestList.getModel();
        //RequestList.setModel(cmodel);
        logger4j.debug("RequestList.repaint called.");
        RequestList.repaint();
    }
    
    public void updaterlist(List<PRequestResponse> rlist){
        this.rlist = rlist;
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
        RequestEdit = new javax.swing.JPopupMenu();
        edit = new javax.swing.JMenuItem();
        restore = new javax.swing.JMenuItem();
        update = new javax.swing.JMenuItem();
        ResponseShow = new javax.swing.JPopupMenu();
        show = new javax.swing.JMenuItem();
        jScrollPane2 = new javax.swing.JScrollPane();
        jPanel4 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        RequestList = new javax.swing.JList<>();
        paramlog = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        jScrollPane4 = new javax.swing.JScrollPane();
        MacroRequest = new javax.swing.JTextPane();
        jPanel2 = new javax.swing.JPanel();
        jScrollPane6 = new javax.swing.JScrollPane();
        MacroResponse = new javax.swing.JTextPane();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane5 = new javax.swing.JScrollPane();
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
        MBtoStepNo = new javax.swing.JCheckBox();
        MBmonitorofprocessing = new javax.swing.JCheckBox();
        UpSelected = new javax.swing.JButton();
        DownSelected = new javax.swing.JButton();

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

        jPanel4.setPreferredSize(new java.awt.Dimension(871, 1400));

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

        paramlog.setPreferredSize(new java.awt.Dimension(847, 300));
        paramlog.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                paramlogStateChanged(evt);
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
        jScrollPane4.setViewportView(MacroRequest);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(0, 0, 0)
                .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE)
                .addGap(0, 0, 0))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 302, Short.MAX_VALUE)
        );

        paramlog.addTab(bundle.getString("MacroBuilderUI.リクエスト.text"), jPanel1); // NOI18N

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
        jScrollPane6.setViewportView(MacroResponse);

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE)
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 302, Short.MAX_VALUE)
        );

        paramlog.addTab(bundle.getString("MacroBuilderUI.レスポンス.text"), jPanel2); // NOI18N

        jScrollPane5.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        MacroComments.setColumns(20);
        MacroComments.setLineWrap(true);
        MacroComments.setRows(5);
        jScrollPane5.setViewportView(MacroComments);

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 835, Short.MAX_VALUE)
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane5, javax.swing.GroupLayout.DEFAULT_SIZE, 302, Short.MAX_VALUE)
        );

        paramlog.addTab(bundle.getString("MacroBuilderUI.追跡.text"), jPanel3); // NOI18N

        ParamTracking.setText(bundle.getString("MacroBuilderUI.追跡.text")); // NOI18N
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

        ClearMacro.setText(bundle.getString("MacroBuilderUI.クリア.text")); // NOI18N
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

        jLabel2.setText(bundle.getString("MacroBuilderUI.マクロリクエスト一覧.text")); // NOI18N

        jPanel5.setBorder(javax.swing.BorderFactory.createTitledBorder(bundle.getString("MacroBuilderUI.TakeOverCache.text"))); // NOI18N

        CBinheritFromCache.setSelected(true);
        CBinheritFromCache.setText(bundle.getString("MacroBuilderUI.TakeOverCacheCheckBox.text")); // NOI18N
        CBinheritFromCache.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CBinheritFromCacheActionPerformed(evt);
            }
        });

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
        jLabel3.setText("<HTML>\n<DL>\n<BR>\n<LI>baseline(experimental): you can test(tamper) tracking tokens with scanner/intruder which has baseline request.\n<LI>replace(default): Tracking tokens is completely replaced with extracted value from previous page's response.\n<BR><BR>* For Details , refer ?button in the \"baseline/replace mode\" section. \n<DL>\n</HTML>");
        jLabel3.setVerticalAlignment(javax.swing.SwingConstants.BOTTOM);

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
                .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
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
                    .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 111, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jCheckBox2.setText("WaitTimer(sec)");
        jCheckBox2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jCheckBox2ActionPerformed(evt);
            }
        });

        waitsec.setText("0");

        MBfromStepNo.setText(bundle.getString("MacroBuilderUI.追跡FROM設定.text")); // NOI18N
        MBfromStepNo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                MBfromStepNoActionPerformed(evt);
            }
        });

        jLabel1.setText("Other Options(Usually, you do not need chage options below.)");

        jPanel7.setBorder(javax.swing.BorderFactory.createTitledBorder("Pass back to the invoking tool"));

        FinalResponse.setSelected(true);
        FinalResponse.setText(bundle.getString("MacroBuilderUI.FINAL RESPONSE.text")); // NOI18N
        FinalResponse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FinalResponseActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel7Layout = new javax.swing.GroupLayout(jPanel7);
        jPanel7.setLayout(jPanel7Layout);
        jPanel7Layout.setHorizontalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addComponent(FinalResponse, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel7Layout.setVerticalGroup(
            jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel7Layout.createSequentialGroup()
                .addComponent(FinalResponse, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );

        MBtoStepNo.setText(bundle.getString("MacroBuilderUI.MBtoStepNo.text")); // NOI18N

        MBmonitorofprocessing.setText(bundle.getString("MacroBuilderUI.MBmonitorofprocessing.text")); // NOI18N
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

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jPanel7, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jPanel6, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jPanel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addComponent(jScrollPane1)
                                .addGap(12, 12, 12)
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(custom, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(ClearMacro, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(ParamTracking, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(Load, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(Save, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(StartScan, javax.swing.GroupLayout.PREFERRED_SIZE, 111, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(UpSelected, javax.swing.GroupLayout.PREFERRED_SIZE, 111, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(DownSelected, javax.swing.GroupLayout.PREFERRED_SIZE, 111, javax.swing.GroupLayout.PREFERRED_SIZE))))
                        .addGap(26, 26, 26))
                    .addComponent(jSeparator1)
                    .addGroup(jPanel4Layout.createSequentialGroup()
                        .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 402, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(jPanel4Layout.createSequentialGroup()
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                                        .addComponent(jCheckBox2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addGap(18, 18, 18)
                                        .addComponent(waitsec, javax.swing.GroupLayout.PREFERRED_SIZE, 68, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(71, 71, 71))
                                    .addGroup(jPanel4Layout.createSequentialGroup()
                                        .addComponent(MBfromStepNo, javax.swing.GroupLayout.PREFERRED_SIZE, 310, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(26, 26, 26)))
                                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(MBtoStepNo, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(MBmonitorofprocessing, javax.swing.GroupLayout.PREFERRED_SIZE, 405, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 826, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel4Layout.createSequentialGroup()
                        .addComponent(paramlog, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addContainerGap())))
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 284, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel4Layout.createSequentialGroup()
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
                        .addComponent(StartScan)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(paramlog, javax.swing.GroupLayout.PREFERRED_SIZE, 328, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jPanel5, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jPanel7, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabel1)
                .addGap(18, 18, 18)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jCheckBox2)
                    .addComponent(waitsec, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(MBmonitorofprocessing))
                .addGap(43, 43, 43)
                .addGroup(jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(MBfromStepNo)
                    .addComponent(MBtoStepNo))
                .addContainerGap(255, Short.MAX_VALUE))
        );

        jScrollPane2.setViewportView(jPanel4);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 870, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 1283, Short.MAX_VALUE)
        );

        getAccessibleContext().setAccessibleName("");
    }// </editor-fold>//GEN-END:initComponents

    private void customActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_customActionPerformed
        // TODO add your handling code here:
        List<String> poslist = RequestList.getSelectedValuesList();
        ArrayList<PRequestResponse> messages = new ArrayList<PRequestResponse>();
        if(rlist!=null) {

            for (String s : poslist) {
                String[] values = s.split("[|]", 0);
                if (values.length > 0) {
                    int i = Integer.parseInt(values[0]);
                    PRequestResponse pqr = rlist.get(i);
                    pqr.setMacroPos(i);
                    messages.add(pqr);
                }
            }
        }
            
            if(ParmGen.twin==null){
                    ParmGen.twin = new ParmGenTop(pmt, new ParmGenJSONSave(pmt,
                        messages)
                        );
            }
            
            ParmGen.twin.VisibleWhenJSONSaved(this);
            

    }//GEN-LAST:event_customActionPerformed

    private void MacroRequestLoadContents(){
                
        if(selected_request_idx!=-1&&!isLoadedMacroRequestContents) {
            PRequestResponse pqr = rlist.get(selected_request_idx);

            ParmGenTextDoc reqdoc = new ParmGenTextDoc(MacroRequest);

            reqdoc.setRequestChunks(pqr.request);

            isLoadedMacroRequestContents = true;
        }
    }
    
    private void MacroResponseLoadContents(){
                
        if(selected_request_idx!=-1&&!isLoadedMacroResponseContents){
            PRequestResponse pqr = rlist.get(selected_request_idx);
            
            ParmGenTextDoc resdoc = new ParmGenTextDoc(MacroResponse);
            resdoc.setResponseChunks(pqr.response);
            isLoadedMacroResponseContents = true;
        }
    }
    
    private void MacroCommentLoadContents(){

        if(selected_request_idx!=-1&&!isLoadedMacroCommentContents){
            PRequestResponse pqr = rlist.get(selected_request_idx);
            MacroComments.setText(pqr.getComments());
            isLoadedMacroCommentContents = true;
        }
    }
    
    private void paramlogTabbedPaneSelectedContentsLoad(){
        int selIndex = paramlog.getSelectedIndex();//tabbedpanes selectedidx 0start..
        switch(selIndex){
            case 0:
                MacroRequestLoadContents();
                break;
            case 1:
                MacroResponseLoadContents();
                break;
            case 2:
                MacroCommentLoadContents();
                break;
            default:
                MacroRequestLoadContents();
                break;
        }
    }
    
    private void RequestListValueChanged(javax.swing.event.ListSelectionEvent evt) {//GEN-FIRST:event_RequestListValueChanged
        // TODO add your handling code here:
        
        // below magical coding needs ,,,
        if (evt.getValueIsAdjusting()) {
            // The user is still manipulating the selection.
            return;
        }
        
        logger4j.debug("RequestListValueChanged Start...");
        int pos = RequestList.getSelectedIndex();
        if (pos != -1) {
            logger4j.debug("RequestListValueChanged selected pos:" + pos);
            if (rlist != null && rlist.size() > pos) {
                //

                selected_request_idx = pos;
                isLoadedMacroCommentContents = false;
                isLoadedMacroRequestContents = false;
                isLoadedMacroResponseContents = false;

                paramlogTabbedPaneSelectedContentsLoad();

            }
        } else {
            logger4j.debug("RequestListValueChanged noselect pos:" + pos);
        }
        logger4j.debug("RequestListValueChanged done");
    }//GEN-LAST:event_RequestListValueChanged

    private void CBinheritFromCacheActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CBinheritFromCacheActionPerformed
        // TODO add your handling code here:
        pmt.setCBInheritFromCache(CBinheritFromCache.isSelected());
    }//GEN-LAST:event_CBinheritFromCacheActionPerformed

    private void jCheckBox2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jCheckBox2ActionPerformed
        // TODO add your handling code here:
        if(jCheckBox2.isSelected()){
            pmt.setWaitTimer(waitsec.getText());
        }else{
            pmt.setWaitTimer("0");
        }
    }//GEN-LAST:event_jCheckBox2ActionPerformed

    private void FinalResponseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FinalResponseActionPerformed
        // TODO add your handling code here:
        pmt.setMBFinalResponse(FinalResponse.isSelected());
    }//GEN-LAST:event_FinalResponseActionPerformed

    private void RequestListMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_RequestListMousePressed
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {
            PopupMenuForRequestList.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_RequestListMousePressed

    private void disableRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_disableRequestActionPerformed
        // TODO add your handling code here:
        int pos = RequestList.getSelectedIndex();
        if (pos != -1) {
            pmt.DisableRequest(pos);
        }
        Redraw();
    }//GEN-LAST:event_disableRequestActionPerformed

    private void enableRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_enableRequestActionPerformed
        // TODO add your handling code here:
        int pos = RequestList.getSelectedIndex();
        if (pos != -1) {
            pmt.EnableRequest(pos);
        }
        Redraw();
    }//GEN-LAST:event_enableRequestActionPerformed

    private void RequestListMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_RequestListMouseClicked
        // TODO add your handling code here:
        if (evt.isPopupTrigger()) {
            PopupMenuForRequestList.show(evt.getComponent(), evt.getX(), evt.getY());
        }
        if ((evt.getModifiers() & InputEvent.BUTTON1_MASK) != 0) { // left button clicked
            int sidx = RequestList.locationToIndex(evt.getPoint());
            if (sidx > -1) {
                logger4j.debug("RequestList mouse left button clicked: sidx:" + sidx);
                if (selected_request_idx == sidx){
                    RequestList.clearSelection();
                    RequestList.setSelectedIndex(sidx);
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
        ParmFileFilter pFilter = new ParmFileFilter();
        jfc.setFileFilter(pFilter);
        List<PRequestResponse> orglist = pmt.getOriginalrlist();
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

            //token追跡自動設定。。
            //ArrayList<ParmGenToken> tracktokenlist = new ArrayList<ParmGenToken>();
            ArrayList<ParmGenResToken> urltokens = new ArrayList<ParmGenResToken>();
            Pattern patternw32 = ParmGenUtil.Pattern_compile("\\w{32}");

            List<AppParmsIni> newparms = new ArrayList<AppParmsIni>();//生成するパラメータ
            PRequestResponse respqrs = null;
            //int row = 0;
            int pos = 0;

            for (PRequestResponse pqrs : orglist) {
                HashMap<ParmGenTrackingToken, String> addedtokens = new HashMap<ParmGenTrackingToken, String>();
                for(ListIterator<ParmGenResToken> it = urltokens.listIterator(urltokens.size());it.hasPrevious();){//urltokens: extracted tokenlist from Response. 
                    //for loop order: fromStepno in descending order(hasPrevious)
                
                    //リクエストにtracktokenlistのトークンが含まれる場合のみ
                    ParmGenResToken restoken = it.previous();
                    int fromStepNo = restoken.fromStepNo;
                    ArrayList<ParmGenTrackingToken> requesttokenlist = new ArrayList<ParmGenTrackingToken>();
                    
                    for(int phase = 0 ; phase<2; phase++){//phase 0: request's token name & value matched,then add to request token list
                        // phase 1: request's token name matched. then add to request token list.
                        for (ParmGenToken tkn : restoken.tracktokenlist) {
                            String token = tkn.getTokenKey().getName();
                            String value = tkn.getTokenValue().getValue();
                            ParmGenGSONDecoder reqjdecoder = new ParmGenGSONDecoder(pqrs.request.getBodyStringWithoutHeader());

                            List<ParmGenToken> reqjtklist = reqjdecoder.parseJSON2Token();

                            ParmGenRequestToken _QToken = null;
                            ParmGenToken _RToken = null;
                            for(ParmGenToken reqtkn : reqjtklist){
                                if((reqtkn.getTokenKey().getName().equals(token)&& reqtkn.getTokenValue().getValue().equals(value))||(phase==1 && reqtkn.getTokenKey().getName().equals(token))){// same name && value
                                    //We found json tracking parameter in request.  
                                    _RToken = tkn;
                                    _QToken = new ParmGenRequestToken(reqtkn);
                                    
                                    ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, null);
                                    if(!addedtokens.containsKey(tracktoken)){
                                        requesttokenlist.add(tracktoken);
                                        addedtokens.put(tracktoken, "");
                                    }
                                }
                            }



                            ParmGenRequestToken query_token = pqrs.request.getRequestQueryToken(token);
                            ParmGenRequestToken body_token = pqrs.request.getRequestBodyToken(token);
                            logger4j.debug("phase:" + phase +" token[" + token + "] value[" + value + "]");
                            //phase==0: token name & value matched
                            //phase==1: token name matched only. we don't care value.
                            if (pqrs.request.hasQueryParam(token, value) || pqrs.request.hasBodyParam(token, value)
                                    || (phase==1 && (pqrs.request.hasQueryParamName(token) || pqrs.request.hasBodyParamName(token)))) {

                                //add a token to  Query / Body Request parameter. 
                                switch(tkn.getTokenKey().GetTokenType()){
                                case ACTION:
                                case HREF:

                                    ParmGenParseURL _psrcurl = new ParmGenParseURL(tkn.getTokenValue().getURL());
                                    ParmGenParseURL _pdesturl = new ParmGenParseURL(pqrs.request.getURL());
                                    String srcurl = _psrcurl.getPath();
                                    String desturl = _pdesturl.getPath();
                                    logger4j.debug( "srcurl|desturl:[" + srcurl + "]|[" + desturl + "]");
                                    if(desturl.indexOf(srcurl)!=-1){// ACTION SRC/HREF attribute's path == destination request path
                                        _RToken = tkn;
                                        if(query_token !=null){
                                            //We found same name/value ACTION/HREF's query paramter in request's query parameter.
                                            _QToken = query_token;
                                            ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, null);
                                            if(!addedtokens.containsKey(tracktoken)){
                                                requesttokenlist.add(tracktoken);
                                                addedtokens.put(tracktoken, "");
                                            }
                                        }
                                    }
                                    break;
                                default:
                                    _RToken = tkn;
                                    if(query_token !=null){
                                        //We found same name/value INPUT TAG(<INPUT type=...>)'s paramter in request's query parameter.
                                        _QToken = query_token;
                                        ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, null);
                                        if(!addedtokens.containsKey(tracktoken)){
                                            requesttokenlist.add(tracktoken);
                                            addedtokens.put(tracktoken, "");
                                        }
                                    }
                                    if(body_token!=null){
                                        //We found same name/value INPUT TAG(<INPUT type=...>)'s paramter in request's body parameter.
                                        _QToken = body_token;
                                        ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, null);
                                        if(!addedtokens.containsKey(tracktoken)){
                                            requesttokenlist.add(tracktoken);
                                            addedtokens.put(tracktoken, "");
                                        }
                                    }
                                    break;
                                }
                            }
                            
                            //bearer/cookie header parameter
                            ArrayList<HeaderPattern> hlist = pqrs.request.hasHeaderMatchedValue(value);
                            if(hlist!=null&&hlist.size()>0){
                                for(HeaderPattern hpattern: hlist){
                                    _QToken = hpattern.getQToken();
                                    _RToken = tkn;
                                    ParmGenTrackingToken tracktoken = new ParmGenTrackingToken(_QToken, _RToken, hpattern.getTokenValueRegex());
                                    if(!addedtokens.containsKey(tracktoken)){
                                        requesttokenlist.add(tracktoken);
                                        addedtokens.put(tracktoken, "");
                                    }
                                }
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
                            
                            ParmGenRequestToken _QToken = PGTtkn.getRequestToken();
                            ParmGenToken _RToken = PGTtkn.getResponseToken();
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
                                encodedregex = URLEncoder.encode(regex, ParmVars.enc.getIANACharsetName());
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
                    ParmGenResToken trackurltoken = new ParmGenResToken();
                    //trackurltoken.request = pqrs.request;
                    trackurltoken.tracktokenlist = new ArrayList<ParmGenToken>();
                    InterfaceCollection<ParmGenToken> ic = pqrs.response.getLocationTokens(tklist);
                    //JSON parse
                    ParmGenGSONDecoder jdecoder = new ParmGenGSONDecoder(body);
                    List<ParmGenToken> jtklist = jdecoder.parseJSON2Token();

                    //add extracted tokens to tklist
                    tklist.addAll(bodytklist);
                    tklist.addAll(jtklist);

                    for (ParmGenToken token : tklist) {
                        //PHPSESSID, token, SesID, jsessionid
                        String tokenname = token.getTokenKey().getName();
                        boolean namematched = false;
                        for (String tkn : tknames) {//予約語に一致 
                            if (tokenname.equalsIgnoreCase(tkn)) {//完全一致 tokenname  that matched reserved token name
                                namematched = true;
                                break;
                            }
                        }
                        if (!namematched) {//nameはtknamesに一致しない
                            for (String tkn : tknames) {
                                if (tokenname.toUpperCase().indexOf(tkn.toUpperCase()) != -1) {//予約語に部分一致 tokenname that partially matched reserved token name
                                    namematched = true;
                                    break;
                                }
                            }
                        }
                        // value値がToken値だとみられる
                        if (!namematched) {//nameはtknamesに一致しない
                            String tokenvalue = token.getTokenValue().getValue();

                            if (ParmGenUtil.isTokenValue(tokenvalue)) {// token value that looks like tracking token
                                namematched = true;
                            }
                        }
                        token.setEnabled(namematched);//namematched==true: token that looks like tracking token
                        trackurltoken.tracktokenlist.add(token);
                        trackurltoken.fromStepNo = pos;

                    }

                    if(!trackurltoken.tracktokenlist.isEmpty()){
                        urltokens.add(trackurltoken);
                    }
                    //### skip end
                }else{
                    logger4j.debug("automacro:Response analysis skipped stepno:" + pos + " MIMEtype:" + res_contentMimeType);
                }
                
                
                pos++;
            }
            
            logger4j.debug("newparms.size=" + newparms.size());
            new ParmGenTokenJDialog(null, false, newparms, pmt).setVisible(true);
        }
    }//GEN-LAST:event_ParamTrackingActionPerformed

    private void ClearMacroActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ClearMacroActionPerformed
        // TODO add your handling code here:
        clear();
    }//GEN-LAST:event_ClearMacroActionPerformed

    private void LoadActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_LoadActionPerformed
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

            ParmGen pgen = new ParmGen(pmt);//20200208 なにもしないコンストラクター＞スタティックに置き換える。
            if(pgen.checkAndLoadFile(name)){//20200208 再読み込み -> 明示的なファイルのロード、チェック、チェックOKのみパラメータ更新する。
                //load succeeded..
            }
            
            
        }
        
    }//GEN-LAST:event_LoadActionPerformed

    private void RepeaterActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RepeaterActionPerformed
        // TODO add your handling code here:
    	int pos = RequestList.getSelectedIndex();
        if (pos != -1) {
            pmt.setCurrentRequest(pos);
            pmt.sendToRepeater(pos);

        }
        Redraw();
    }//GEN-LAST:event_RepeaterActionPerformed

    private void ScannerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ScannerActionPerformed
        // TODO add your handling code here:
    	int pos = RequestList.getSelectedIndex();
        if (pos != -1) {
            pmt.setCurrentRequest(pos);
            pmt.sendToScanner(pos);

        }
        Redraw();
    }//GEN-LAST:event_ScannerActionPerformed

    private void IntruderActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_IntruderActionPerformed
        // TODO add your handling code here:
    	int pos = RequestList.getSelectedIndex();
        if (pos != -1) {
            pmt.setCurrentRequest(pos);
            pmt.sendToIntruder(pos);

        }
        Redraw();
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
            boolean filenamechanged = false;
            if(ParmVars.getParmFile()==null||!ParmVars.getParmFile().equals(name)){
                filenamechanged = true;
            }
            ParmVars.setParmFile(name);
             //csv.save();
             ParmGenJSONSave csv = new ParmGenJSONSave(null, pmt);
             csv.GSONsave();
             /*if(filenamechanged){//if filename changed then reload json
                ParmGen pgen = new ParmGen(pmt, null);
                pgen.reset();//再読み込み
             }*/
             
            
        }
        
    }//GEN-LAST:event_SaveActionPerformed

    private void editActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editActionPerformed
        // TODO add your handling code here:
        String reg = "";
        //String orig = MacroRequest.getText();
        
    
        int pos = RequestList.getSelectedIndex();
        if(pos<0)return;
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
        int pos = RequestList.getSelectedIndex();
        String orig = MacroResponse.getText();
        if (pos != -1) {
            StyledDocument doc = MacroResponse.getStyledDocument();
            new ParmGenRegex(this,reg,doc).setVisible(true);
        }
        
    }//GEN-LAST:event_showActionPerformed

    private void StartScanActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_StartScanActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_StartScanActionPerformed

    private void MBmonitorofprocessingActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_MBmonitorofprocessingActionPerformed
        // TODO add your handling code here:
        pmt.setMBmonitorofprocessing(MBmonitorofprocessing.isSelected());
    }//GEN-LAST:event_MBmonitorofprocessingActionPerformed

    private void MBfromStepNoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_MBfromStepNoActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_MBfromStepNoActionPerformed

    private void TrackModeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_TrackModeActionPerformed
        // TODO add your handling code here:
        pmt.setMBreplaceTrackingParam(isReplaceMode());
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

    private void paramlogStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_paramlogStateChanged
        // TODO add your handling code here:
        // jTabbedPane tab select problem fixed. by this eventhandler is defined... what a strange behavior. 
        //int selIndex = paramlog.getSelectedIndex();
	//String t = paramlog.getTitleAt(selIndex);
	//logger4j.info("paramlogStateChanged: title[" + t + "]");
        paramlogTabbedPaneSelectedContentsLoad();
    }//GEN-LAST:event_paramlogStateChanged

    private void UpSelectedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_UpSelectedActionPerformed
        // TODO add your handling code here:
        int pos = RequestList.getSelectedIndex();
        if ( pos > 0 ) {
            // rlist,  RequestList
            logger4j.debug("selected:" + pos);
            // exchange pos and pos-1
            PRequestResponse upobj = rlist.get(pos);
            PRequestResponse downobj = rlist.get(pos-1);
            rlist.set(pos-1, upobj);
            rlist.set(pos, downobj);
            List<PRequestResponse> originalrlist = pmt.getOriginalrlist();
            upobj = originalrlist.get(pos);
            downobj = originalrlist.get(pos-1);
            originalrlist.set(pos-1, upobj);
            originalrlist.set(pos, downobj);

            String upelem = String.format("%03d",pos-1) + '|' + upobj.request.getURL();
            String downelem = String.format("%03d",pos) + '|' + downobj.request.getURL();

            RequestListModel.set(pos-1, upelem);
            RequestListModel.set(pos, downelem);
            ParmGen.exchangeStepNo(pos-1, pos);

            if (ParmVars.isSaved()) { // if you have been saved params. then overwrite. 
                ParmGenJSONSave csv = new ParmGenJSONSave(null, pmt);
                csv.GSONsave();
            }

            RequestList.setSelectedIndex(pos-1);
        }
        
    }//GEN-LAST:event_UpSelectedActionPerformed

    private void DownSelectedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DownSelectedActionPerformed
        // TODO add your handling code here:
        int pos = RequestList.getSelectedIndex();
        int siz = rlist != null ? rlist.size() : 0;
        if ( pos > -1 && pos < siz - 1 ) {
            // rlist,  RequestList
            logger4j.debug("selected:" + pos);
            // exchange pos and pos-1
            PRequestResponse upobj = rlist.get(pos+1);
            PRequestResponse downobj = rlist.get(pos);
            rlist.set(pos, upobj);
            rlist.set(pos+1, downobj);
            List<PRequestResponse> originalrlist = pmt.getOriginalrlist();
            upobj = originalrlist.get(pos+1);
            downobj = originalrlist.get(pos);
            originalrlist.set(pos, upobj);
            originalrlist.set(pos+1, downobj);

            String upelem = String.format("%03d",pos) + '|' + upobj.request.getURL();
            String downelem = String.format("%03d",pos+1) + '|' + downobj.request.getURL();

            RequestListModel.set(pos, upelem);
            RequestListModel.set(pos+1, downelem);
            ParmGen.exchangeStepNo(pos, pos+1);

            if (ParmVars.isSaved()) { // if you have been saved params. then overwrite. 
                ParmGenJSONSave csv = new ParmGenJSONSave(null, pmt);
                csv.GSONsave();
            }

            RequestList.setSelectedIndex(pos+1);
        }
    }//GEN-LAST:event_DownSelectedActionPerformed

    private void deleteRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteRequestActionPerformed
        // TODO add your handling code here:
        int pos = RequestList.getSelectedIndex();
        if ( pos != -1 ) {
            List<AppParmsIni> hasposlist = ParmGen.getAppParmIniHasStepNoSpecified(pos);
            if ( !hasposlist.isEmpty()) {
                PRequestResponse pqrs = rlist.get(pos);
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
            rlist.remove(pos);
            RequestListModel.remove(pos);
            selected_request_idx = -1;
            List<PRequestResponse> originalrlist = pmt.getOriginalrlist();
            originalrlist.remove(pos);

            for(int i = pos; i < RequestListModel.size(); i++) {
                PRequestResponse pqrs = rlist.get(i);
                String elem = String.format("%03d",i) + '|' + pqrs.request.getURL();
                RequestListModel.set(i, elem);
            }
            int siz = rlist.size();
            if ( pos == siz - 1 && siz > 1) {
                int npos = pos - 1;
                RequestList.setSelectedIndex(npos);
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
                ParmGenJSONSave csv = new ParmGenJSONSave(null, pmt);
                csv.GSONsave();
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
        if (evt.isPopupTrigger()) {// popup menu trigger occured. 
            logger4j.debug("MacroResponseMouseClicked PoupupTriggered.");
            ResponseShow.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_MacroResponseMouseClicked

    private void MacroResponseMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_MacroResponseMousePressed
        // TODO add your handling code here:
        logger4j.debug( "MacroResponseMousePressed...start");
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
        // TODO add your handling code here:
        int idx = this.getCurrentSelectedRequestIndex();
        if (pmt != null && idx > -1 && rlist != null && idx < rlist.size()) {
            PRequestResponse prr = pmt.getOriginalRequest(idx);
            if (prr != null) {
                PRequestResponse current = pmt.getRequestResponseCurrentList(idx);
                current.updateRequestResponse(prr.request.clone(), prr.response.clone());
                ParmGenTextDoc reqdoc = new ParmGenTextDoc(MacroRequest);
                reqdoc.setRequestChunks(prr.request);
                ParmGenTextDoc resdoc = new ParmGenTextDoc(MacroResponse);
                resdoc.setResponseChunks(prr.response);
            }
        }
    }//GEN-LAST:event_restoreActionPerformed

    private void updateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_updateActionPerformed
        // TODO add your handling code here:
        int idx = this.getCurrentSelectedRequestIndex();
        if (pmt != null && idx > -1 && rlist != null && idx < rlist.size()) {
            PRequestResponse current = pmt.getRequestResponseCurrentList(idx);
            StyledDocumentWithChunk doc = this.getMacroRequestStyledDocument();
            if (doc != null) {
                PRequest newrequest = doc.reBuildPRequestFromDocTextAndChunks(); // request newly created from DocText and Chunks
                current.request = newrequest;

                PRequestResponse original = pmt.getOriginalRequest(idx);
                original.updateRequestResponse(current.request, current.response);
                if (ParmVars.isSaved()) { // if you have been saved params. then overwrite. 
                    ParmGenJSONSave csv = new ParmGenJSONSave(null, pmt);
                    csv.GSONsave();
                }
            }
        }
    }//GEN-LAST:event_updateActionPerformed

    /**
     * get current selected request index in RequestList.
     * 
     * @return int
     */
    public int getCurrentSelectedRequestIndex(){
        int pos = RequestList.getSelectedIndex();
        if (pos < rlist.size()) return pos;
        return -1;
    }

    public StyledDocumentWithChunk getMacroRequestStyledDocument() {
        int pos = getCurrentSelectedRequestIndex();
        if (pos < 0 || pos != selected_request_idx) {
            logger4j.error(
                    "getMacroRequestStyledDocument pos["
                            + pos
                            + "]!=selected_request_idx["
                            + selected_request_idx + "]");
            return null;
        }
        MacroRequestLoadContents();
        StyledDocument doc =  MacroRequest.getStyledDocument();
        if ( doc instanceof StyledDocumentWithChunk) {
            return CastUtils.castToType(doc);
        }
        return null;
    }
    
    public String getMacroRequest() {
        return MacroRequest.getText();
    }
    
    @Override
    public void ParmGenRegexSaveAction(StyledDocumentWithChunk doc) {
        int idx = getCurrentSelectedRequestIndex();
        if(rlist != null && idx > -1 &&  idx < rlist.size()){
            try {
                PRequest newrequest = doc.reBuildPRequestFromDocTextAndChunks();
                if (newrequest != null) {
                    pmt.updateRequestCurrentList(idx, newrequest);
                    ParmGenTextDoc ndoc = new ParmGenTextDoc(MacroRequest);
                    ndoc.setRequestChunks(newrequest);
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
    private javax.swing.JMenuItem disableRequest;
    private javax.swing.JMenuItem edit;
    private javax.swing.JMenuItem enableRequest;
    private javax.swing.JButton jButton1;
    private javax.swing.JCheckBox jCheckBox2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JTabbedPane paramlog;
    private javax.swing.JMenuItem restore;
    private javax.swing.JMenuItem show;
    private javax.swing.JMenuItem update;
    private javax.swing.JTextField waitsec;
    // End of variables declaration//GEN-END:variables


}