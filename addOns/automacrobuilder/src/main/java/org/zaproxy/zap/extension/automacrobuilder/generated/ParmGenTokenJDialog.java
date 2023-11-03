/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.ResourceBundle;
import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.table.DefaultTableModel;

import org.zaproxy.zap.extension.automacrobuilder.*;

/**
 *
 * @author gdgd009xcd
 */
@SuppressWarnings("serial")
public class ParmGenTokenJDialog extends javax.swing.JDialog {

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");
    MacroBuilderUI mbui = null;
    List<AppParmsIni> newparms = null;
    List<PRequestResponse> newPRequestResponseList = null;
    ParmGenMacroTrace pmt = null;
    ParmGenMacroTraceProvider pmtProvider = null;

    private String choosedFileName = null;

    /**
     * Creates new form ParmGenTokenJDialog
     */
    public ParmGenTokenJDialog(MacroBuilderUI mbui,
                               String choosedFileName,
                               ParmGenMacroTraceProvider pmtProvider,
                               ModalityType modal,
                               List<PRequestResponse> newPRequestResponseList,
                               List<AppParmsIni> _newparms,
                               ParmGenMacroTrace _pmt) {
        super(SwingUtilities.windowForComponent(mbui), bundle.getString("ParmGenTokenJDialog.DialogTitle.text"), modal);
        this.mbui = mbui;
        this.choosedFileName = choosedFileName;
        this.pmtProvider = pmtProvider;
        initComponents();
        this.newPRequestResponseList = newPRequestResponseList;
        this.newparms = _newparms;
        this.pmt = _pmt;
        //　Display the list of tracking tokens extracted from newparms
        HashMap<ParmGenTokenKey, ParmGenTokenValue> map = new HashMap<ParmGenTokenKey, ParmGenTokenValue>();
        ParmGenTokenKey tkey = null;
        ParmGenTokenValue tval = null;
        ParmGenToken token = null;
        for(AppParmsIni pini: newparms){
            for(AppValue ap: pini.getAppValueReadWriteOriginal()){
                tkey = new ParmGenTokenKey(ap.getTokenType(), ap.getToken(), ap.getResRegexPos());
                tval = new ParmGenTokenValue(ap.getresURL(), ap.getResFetchedValue(), ap.isEnabled());
                map.put(tkey, tval);
            }
        }
        
        // clear table contents
        DefaultTableModel model = (DefaultTableModel)trackTkTable.getModel();
        while(model.getRowCount()>0){//delete all table rows
            model.removeRow(0);
        }
        
        for(Map.Entry<ParmGenTokenKey, ParmGenTokenValue> entry : map.entrySet()) {
            tkey = entry.getKey();
            tval = entry.getValue();
            boolean enabled = tval.getBoolean();
            Object[] rec = new Object[] {tval.getBoolean(),"", tkey.GetTokenType().name(), Integer.toString(tkey.getFcnt()),tkey.getName(),tval.getValue()};
            model.addRow(rec);
        }

        pack();
        setLocationRelativeTo(getOwner());
    }

    /**
     * create swing components.
     * This code is modified manually.
     */
    @SuppressWarnings({"unchecked","rawtypes","serial"})
    private void initComponents() {

        mainPanel = new javax.swing.JPanel();
        trackTkScrollPane = new javax.swing.JScrollPane();
        trackTkTable = new javax.swing.JTable();
        jSeparator1 = new javax.swing.JSeparator();
        OK = new javax.swing.JButton();
        cancelButton = new javax.swing.JButton();
        descriptionLabel = new javax.swing.JLabel();
        initTrackCheckBox = new javax.swing.JCheckBox();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        trackTkTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                    bundle.getString("ParmGenTokenJDialog.trackTkTable.columnName0.text"),
                    bundle.getString("ParmGenTokenJDialog.trackTkTable.columnName1.text"),
                    bundle.getString("ParmGenTokenJDialog.trackTkTable.columnName2.text"),
                    bundle.getString("ParmGenTokenJDialog.trackTkTable.columnName3.text"),
                    bundle.getString("ParmGenTokenJDialog.trackTkTable.columnName4.text"),
                    bundle.getString("ParmGenTokenJDialog.trackTkTable.columnName5.text")
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Boolean.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        trackTkTable.getTableHeader().setReorderingAllowed(false);
        trackTkScrollPane.setViewportView(trackTkTable);

        OK.setText("OK");
        OK.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                OKActionPerformed(evt);
            }
        });

        cancelButton.setText("Cancel");
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        descriptionLabel.setText(bundle.getString("ParmGenTokenJDialog.SelectParamLabel1.text")); // NOI18N

        LineBorder border = new LineBorder(Color.green, 1, true);
        initTrackCheckBox.setBorder(border);
        initTrackCheckBox.setText(bundle.getString("ParmGenTokenJDialog.initTrackCheckBox.text"));
        initTrackCheckBox.setToolTipText(bundle.getString("ParmGenTokenJDialog.initTrackCheckBox.toolTip.text"));
        initTrackCheckBox.setBorderPainted(true);

        javax.swing.GroupLayout mainPanelLayout = new javax.swing.GroupLayout(mainPanel);
        mainPanel.setLayout(mainPanelLayout);
        /**
         *   layout<br>
         *
         * <pre>
         *       -------- horizontal ------------>
         * + +-------------------------------------------------+
         * + |  description                    [x]autoTrack    |
         * V |  +--------------------------------------------+ |
         * e |  |                                            | |
         * r |  |          trackTkScrollPane                 | |
         * t |  |                                            | |
         * i |  +--------------------------------------------+ |
         * c +-------------------------------------------------+
         * a | | OK |                               |  CANCEL ||
         * l +-------------------------------------------------
         * ↓
         * </pre>
         */
        mainPanelLayout.setHorizontalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING) // pararellGroup 1
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addComponent(descriptionLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 265, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 1, Short.MAX_VALUE)
                        .addComponent(initTrackCheckBox, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 2, 2))
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addComponent(trackTkScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 375, Short.MAX_VALUE)
                        .addGap(1, 1, 1))
                    .addGroup(mainPanelLayout.createSequentialGroup()
                        .addComponent(OK)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 298, Short.MAX_VALUE)
                        .addComponent(cancelButton))
                    .addComponent(jSeparator1))
                .addContainerGap())
        );
        mainPanelLayout.setVerticalGroup(
            mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(mainPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(mainPanelLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                        .addComponent(descriptionLabel)
                        .addComponent(initTrackCheckBox))
                .addGap(29, 29, 29)
                .addComponent(trackTkScrollPane, javax.swing.GroupLayout.DEFAULT_SIZE, 163, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(mainPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(OK)
                    .addComponent(cancelButton))
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 400, Short.MAX_VALUE) // Adding a gap to a parallelgroup causes all content sizes to be the same as gap.
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, 0)
                    .addComponent(mainPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGap(0, 0, 0)))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 300, Short.MAX_VALUE) // Adding a gap to a parallelgroup causes all content sizes to be the same as gap.
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(0, 0, 0)
                    .addComponent(mainPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGap(0, 0, 0)))
        );

        pack();
    }

    private void OKActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_OKActionPerformed
        // TODO add your handling code here:
        DefaultTableModel model = (DefaultTableModel)trackTkTable.getModel();
        HashMap<ParmGenTokenKey, ParmGenTokenValue> map = new HashMap<ParmGenTokenKey, ParmGenTokenValue>();

        for (int i = 0;i < model.getRowCount();i++ ){
            boolean enabled = Boolean.parseBoolean(model.getValueAt(i, 0).toString());
            String resAttrName = (String)model.getValueAt(i, 1);//input type　Attribute
            String tokentypename = (String)model.getValueAt(i, 2);//tag name eg. input
            int fcnt = Integer.parseInt((String)model.getValueAt(i, 3));//Appearance number: ascending order　0start
            String tokenname = (String)model.getValueAt(i, 4);//token name
            String resFetchedValue = (String)model.getValueAt(i, 5);//token value
            ParmGenTokenKey tkey = new ParmGenTokenKey(AppValue.parseTokenTypeName(tokentypename),tokenname, fcnt);
            ParmGenTokenValue tval = new ParmGenTokenValue(resAttrName, resFetchedValue, enabled);
            map.put(tkey, tval);
        }
        
        
        if (newparms != null && !newparms.isEmpty()&& pmt!=null) {
            List<AppParmsIni> alist = newparms;
            ListIterator<AppParmsIni> appit = alist.listIterator();
            while(appit.hasNext()){
                AppParmsIni aini = appit.next();
                List<AppValue> apvlist = aini.getAppValueReadWriteOriginal();
                ListIterator<AppValue> apvit = null;
                if(apvlist!=null){
                    apvit = apvlist.listIterator();
                    while(apvit.hasNext()){
                        AppValue ap = apvit.next();
                        ParmGenTokenKey _tkey = new ParmGenTokenKey(ap.getTokenType(), ap.getToken(), ap.getResRegexPos());
                        if(map.containsKey(_tkey)){
                            ParmGenTokenValue _tval = map.get(_tkey);
                            if(_tval.getBoolean()){
                                ap.setEnabled(_tval.getBoolean());
                                apvit.set(ap);
                            }else{
                                apvit.remove();
                            }
                        }
                    }
                    if(apvlist.size()<=0){
                        apvlist = null;
                    }
                }
                if(apvlist!=null){
                    //appit.set(aini); no need set
                }else{
                    appit.remove();
                }
            }
            
            
        }

        // Duplicate registration parameter deletion
        List<AppParmsIni> appParmsIniList = pmt.getAppParmsIniList();
        List<AppParmsIni> resultlist = null;

        LOGGER4J.debug("newparms size=" + (newparms!=null?newparms.size():"null"));
        if ( appParmsIniList!= null && newparms != null && !initTrackCheckBox.isSelected()) {// merge newparms to existing one.
            List<AppParmsIni> merged = new ArrayList<>();
            newparms.stream().forEach(newpini -> {
                long samecnt = appParmsIniList.stream().filter(oldpini ->
                        newpini.isSameContents(oldpini)
                ).count();
                if (samecnt <= 0) {
                    merged.add(newpini);
                }
            });
            resultlist = merged;
            resultlist.addAll(appParmsIniList);
        } else if (newparms !=null && !newparms.isEmpty()) { // ParmGen.parmcsv == null && !newparms.isEmpty()
            resultlist = newparms;
        }

        // add new PRequestResponseList.
        this.mbui.addNewRequests(newPRequestResponseList);

        pmt.updateAppParmsIniAndClearCache(resultlist);

        // restore all current requestresponse list with original requestresponse list.
        this.mbui.restoreAllCurrentSelectedMacroRequestFromOriginal();

        ParmGenGSONSaveV2 gson = new ParmGenGSONSaveV2(pmtProvider);
        gson.GSONsave(this.choosedFileName);
        dispose();

    }//GEN-LAST:event_OKActionPerformed

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        // TODO add your handling code here:
        dispose();
    }//GEN-LAST:event_cancelButtonActionPerformed

    /**
     * @param args the command line arguments
     */
    

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton OK;
    private javax.swing.JTable trackTkTable;
    private javax.swing.JButton cancelButton;
    private javax.swing.JLabel descriptionLabel;
    private javax.swing.JPanel mainPanel;
    private javax.swing.JScrollPane trackTkScrollPane;
    private javax.swing.JSeparator jSeparator1;

    private javax.swing.JCheckBox initTrackCheckBox;
    // End of variables declaration//GEN-END:variables
}
