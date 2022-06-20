/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JFileChooser;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.mdepend.ClientDependent;

/**
 *
 * @author tms783
 */
@SuppressWarnings("serial")
public class ParmGenTop extends javax.swing.JFrame {

    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    public ParmGenGSONSaveV2 gson;// json file object
    DefaultTableModel model = null;
    int current_row;
    int default_rowheight;
    boolean ParmGenNew_Modified = false;
    ParmGenMacroTrace pmt;


    private void renderTable(){
        AppParmsIni pini;
        Iterator<AppParmsIni> it = pmt.getIteratorOfAppParmsIni();;
        int ri = 0;
        String FromTo = "";
        while(it.hasNext()){
            pini = it.next();
            int FromStep = pini.getTrackFromStep();
            int ToStep = pini.getSetToStep();
            FromTo = (FromStep>-1?Integer.toString(FromStep):"*") + "->" + (ToStep!=ParmVars.TOSTEPANY?Integer.toString(ToStep):"*");
            if(pini.getTypeVal()!=AppParmsIni.T_TRACK){
                if(ToStep<0||ToStep==ParmVars.TOSTEPANY){
                    FromTo = "*";
                }else{
                    FromTo = Integer.toString(ToStep);
                }
            }
            model.addRow(new Object[] {pini.isPaused(), FromTo, pini.getUrl(), pini.getIniValDsp(), pini.getLenDsp(), pini.getTypeValDspString(),pini.getAppValuesDsp(),pini.getCurrentValue()});
            //ParamTopList.setRowHeight(ri++, default_rowheight * pini.getAppValuesLineCnt());
        }
    }

    private void disableBurpToolGUI() {
        burptoolflg.setVisible(false);
        ProxyScope.setVisible(false);
        IntruderScope.setVisible(false);
        RepeaterScope.setVisible(false);
        ScannerScope.setVisible(false);
    }

       /**
     * Creates new form ParmGenTop
     */
    public ParmGenTop(ParmGenMacroTrace _pmt, ParmGenGSONSaveV2 gson) {
        pmt = _pmt;
        ParmGenNew_Modified = false;
        this.gson = gson;// set reference of ParmGenJSONSaveV2 object
        // initComponents();
        customInitComponents();

        //TableColumnModel tcm = ParamTopList.getColumnModel();
        //tcm.getColumn(6).setCellRenderer(new LineWrapRenderer());
        //ParamTopList.setColumnModel(tcm);
        default_rowheight = ParamTopList.getRowHeight();
        model = (DefaultTableModel)ParamTopList.getModel();

        if(pmt.getClientType() == ClientDependent.CLIENT_TYPE.ZAP) {
            disableBurpToolGUI();
        }

        cleartables();
        DefaultComboBoxModel<String> cbmodel = new DefaultComboBoxModel<String>();
        Encode[] enclist = Encode.values();
        for(Encode charset : enclist){
            cbmodel.addElement(charset.getIANACharsetName());
        }
        LANGUAGE.setModel(cbmodel);
        LANGUAGE.setSelectedItem(pmt.getSequenceEncode().getIANACharsetName());
        renderTable();
        current_row = 0;
        ParmGen pg = new ParmGen(pmt);
        if(ParmGen.ProxyInScope){
            ProxyScope.setSelected(true);
        }else{
            ProxyScope.setSelected(false);
        }
        if(ParmGen.IntruderInScope){
            IntruderScope.setSelected(true);
        }else{
            IntruderScope.setSelected(false);
        }
        if(ParmGen.RepeaterInScope){
            RepeaterScope.setSelected(true);
        }else{
            RepeaterScope.setSelected(false);
        }
        if(ParmGen.ScannerInScope){
            ScannerScope.setSelected(true);
        }else{
            ScannerScope.setSelected(false);
        }
        ParamTopList.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 1) {
                    JTable target = (JTable)e.getSource();
                    int row = target.getSelectedRow();
                    int column = target.getSelectedColumn();
                    // do some action if appropriate column
                    Object cell =  target.getValueAt(row, column);
                    String v = "";
                    if ( cell instanceof String){
                        v = Integer.toString(row) + Integer.toString(column) + (String)cell;
                    }else if(cell instanceof Boolean){
                        v = Integer.toString(row) + Integer.toString(column) + Boolean.toString((boolean)cell);
                        // column == 0 は、pauseボタン。
                        if ( column == 0){
                            List<AppParmsIni> appParmsIniList = pmt.getAppParmsIniList();
                            if (appParmsIniList != null) {
                                AppParmsIni pini = appParmsIniList.get(row);
                                if (pini != null) {
                                    pini.updatePause((boolean) cell);
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    public void refreshRowDisp(boolean reload){
        if(reload){
            if(ParmGen.ProxyInScope){
                ProxyScope.setSelected(true);
            }else{
                ProxyScope.setSelected(false);
            }
            if(ParmGen.IntruderInScope){
                IntruderScope.setSelected(true);
            }else{
                IntruderScope.setSelected(false);
            }
            if(ParmGen.RepeaterInScope){
                RepeaterScope.setSelected(true);
            }else{
                RepeaterScope.setSelected(false);
            }
            if(ParmGen.ScannerInScope){
                ScannerScope.setSelected(true);
            }else{
                ScannerScope.setSelected(false);
            }
            LANGUAGE.setSelectedItem(pmt.getSequenceEncode().getIANACharsetName());
        }
        
        

        cleartables();
        renderTable();
    }

    public void updateRowDisp(AppParmsIni pini){

        if(pini != null){//新規
            List<AppParmsIni> appParmsIniList = pmt.getAppParmsIniList();
            if (appParmsIniList == null) {
                appParmsIniList = new ArrayList<>();
            }
            appParmsIniList.add(pini);
        }
        //overwirte
        gson.GSONsave();
        
        //token cache, cookie clear
        pmt.nullfetchResValAndCookieMan();
        
        refreshRowDisp(false);

    }
    
    /**
     * if the parameters have not been saved, then save them.
     * 
     * @param dialogparent 
     */
    public void VisibleWhenJSONSaved(Component dialogparent){
        if(!ParmVars.isSaved()){
            File cfile = new File(ParmVars.parmfile);
            String dirname = cfile.getParent();
            JFileChooser jfc = new JFileChooser(dirname);
            jfc.setSelectedFile(cfile);
            ParmFileFilter pFilter=new ParmFileFilter();
            jfc.setFileFilter(pFilter);
            if(jfc.showSaveDialog(dialogparent) == JFileChooser.APPROVE_OPTION) {
                //code to handle choosed file here.
                File file = jfc.getSelectedFile();
                String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");
                if(!pFilter.accept(file)){// add extension string if the file name has no extension string
                    name += ".json";
                }
                ParmVars.parmfile = name;
                gson.GSONsave();

            }
        }
        if(ParmVars.isSaved()){
            this.setVisible(true);
        }
    }
    
/*
 *  delete all table rows
 */
    private void cleartables(){
        int rcnt = model.getRowCount();
        for(int i = 0; i< rcnt; i++){
            model.removeRow(0);// remove row zero
        }
    }

    public int getRowSize(){
        if(model==null)return 0;
        return model.getRowCount();
    }
    //
    //
    //　

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings({"unchecked","rawtypes","serial"})
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        LANGUAGE = new javax.swing.JComboBox<>();
        Add = new javax.swing.JButton();
        Mod = new javax.swing.JButton();
        Del = new javax.swing.JButton();
        Cancel = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        ParamTopList = new javax.swing.JTable();
        burptoolflg = new javax.swing.JPanel();
        ProxyScope = new javax.swing.JCheckBox();
        IntruderScope = new javax.swing.JCheckBox();
        ScannerScope = new javax.swing.JCheckBox();
        RepeaterScope = new javax.swing.JCheckBox();
        jLabel2 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle(bundle.getString("ParmGenTop.PARMGENトップ画面.text")); // NOI18N

        jLabel1.setText(bundle.getString("ParmGenTop.文字コード.text")); // NOI18N

        LANGUAGE.setModel(new javax.swing.DefaultComboBoxModel<String>(new String[] { "SJIS", "EUC-JP", "UTF-8", "ISO8859-1", "x-MacCentralEurope" }));
        LANGUAGE.setToolTipText(bundle.getString("ParmGenTop.文字コード.text")); // NOI18N
        LANGUAGE.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                LANGUAGEActionPerformed(evt);
            }
        });

        Add.setText(bundle.getString("ParmGenTop.新規.text")); // NOI18N
        Add.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AddActionPerformed(evt);
            }
        });

        Mod.setText(bundle.getString("ParmGenTop.修正.text")); // NOI18N
        Mod.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ModActionPerformed(evt);
            }
        });

        Del.setText(bundle.getString("ParmGenTop.削除.text")); // NOI18N
        Del.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DelActionPerformed(evt);
            }
        });

        Cancel.setText(bundle.getString("ParmGenTop.閉じる.text")); // NOI18N
        Cancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CancelActionPerformed(evt);
            }
        });

        ParamTopList.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, ".*/input.php.*", null, null, null, null, null},
                {null, null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null, null}
            },
            new String [] {
                "", "FromTo", "", "初期値/CSVファイル", "桁数", "", "パターンリスト", "現在値"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Boolean.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.Integer.class, java.lang.String.class, java.lang.String.class, java.lang.String.class
            };
            boolean[] canEdit = new boolean [] {
                true, false, false, false, false, false, false, false
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        ParamTopList.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        ParamTopList.setRowHeight(18);
        ParamTopList.getTableHeader().setReorderingAllowed(false);
        jScrollPane1.setViewportView(ParamTopList);
        if (ParamTopList.getColumnModel().getColumnCount() > 0) {
            ParamTopList.getColumnModel().getColumn(0).setPreferredWidth(35);
            ParamTopList.getColumnModel().getColumn(0).setHeaderValue(bundle.getString("ParmGenTop.title0.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(2).setPreferredWidth(200);
            ParamTopList.getColumnModel().getColumn(2).setHeaderValue(bundle.getString("ParmGenTop.title1.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(3).setPreferredWidth(150);
            ParamTopList.getColumnModel().getColumn(3).setHeaderValue(bundle.getString("ParmGenTop.title2.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(4).setPreferredWidth(40);
            ParamTopList.getColumnModel().getColumn(4).setHeaderValue(bundle.getString("ParmGenTop.title3.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(5).setPreferredWidth(70);
            ParamTopList.getColumnModel().getColumn(5).setHeaderValue(bundle.getString("ParmGenTop.title4.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(6).setPreferredWidth(200);
            ParamTopList.getColumnModel().getColumn(6).setHeaderValue(bundle.getString("ParmGenTop.title5.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(7).setHeaderValue(bundle.getString("ParmGenTop.title6.text")); // NOI18N
        }

        burptoolflg.setBorder(javax.swing.BorderFactory.createTitledBorder(bundle.getString("ParmGenTop.typeoftool.text"))); // NOI18N

        ProxyScope.setText(bundle.getString("ParmGenTop.PROXY.text")); // NOI18N
        ProxyScope.setEnabled(false);
        ProxyScope.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ProxyScopeActionPerformed(evt);
            }
        });

        IntruderScope.setSelected(true);
        IntruderScope.setText(bundle.getString("ParmGenTop.INTRUDER.text")); // NOI18N
        IntruderScope.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                IntruderScopeActionPerformed(evt);
            }
        });

        ScannerScope.setSelected(true);
        ScannerScope.setText(bundle.getString("ParmGenTop.SCANNER.text")); // NOI18N
        ScannerScope.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ScannerScopeActionPerformed(evt);
            }
        });

        RepeaterScope.setSelected(true);
        RepeaterScope.setText(bundle.getString("ParmGenTop.REPEATER.text")); // NOI18N
        RepeaterScope.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RepeaterScopeActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout burptoolflgLayout = new javax.swing.GroupLayout(burptoolflg);
        burptoolflg.setLayout(burptoolflgLayout);
        burptoolflgLayout.setHorizontalGroup(
            burptoolflgLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(burptoolflgLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(ProxyScope)
                .addGap(18, 18, 18)
                .addComponent(IntruderScope)
                .addGap(32, 32, 32)
                .addComponent(RepeaterScope)
                .addGap(34, 34, 34)
                .addComponent(ScannerScope)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        burptoolflgLayout.setVerticalGroup(
            burptoolflgLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(burptoolflgLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(ProxyScope)
                .addComponent(IntruderScope)
                .addComponent(ScannerScope)
                .addComponent(RepeaterScope))
        );

        jLabel2.setText(bundle.getString("ParmGenTop.注意：処理実行前に、この画面は保存または閉じるボタンで閉じてください。.text")); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(25, 25, 25)
                        .addComponent(Add)
                        .addGap(66, 66, 66)
                        .addComponent(Mod)
                        .addGap(66, 66, 66)
                        .addComponent(Del)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(Cancel))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel1)
                        .addGap(18, 18, 18)
                        .addComponent(LANGUAGE, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(40, 40, 40)
                        .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 472, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 146, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(burptoolflg, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jScrollPane1))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(LANGUAGE, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 43, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(burptoolflg, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(Add)
                    .addComponent(Mod)
                    .addComponent(Del)
                    .addComponent(Cancel))
                .addGap(28, 28, 28))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void ModActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ModActionPerformed
        // TODO add your handling code here:
        //テーブル内の選択したrowに対応するrecをここで渡す。
        int[] rowsSelected = ParamTopList.getSelectedRows();
        AppParmsIni rec = null;
        if ( rowsSelected.length> 0){
            current_row = rowsSelected[0];
            rec = pmt.getAppParmsIni(current_row);
        }
        new ParmGenNew(this, rec).setVisible(true);
    }//GEN-LAST:event_ModActionPerformed

    private void AddActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_AddActionPerformed
        // TODO add your handling code here:
        new ParmGenNew(this, null).setVisible(true);
    }//GEN-LAST:event_AddActionPerformed

    private void CancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CancelActionPerformed
        // TODO add your handling code here:
        ParmGen pgen = new ParmGen(pmt);
        
        pgen.disposeTop();
    }//GEN-LAST:event_CancelActionPerformed

    private void LANGUAGEActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_LANGUAGEActionPerformed
        // TODO add your handling code here:
        int idx = LANGUAGE.getSelectedIndex();
        String str = (String)LANGUAGE.getSelectedItem();  // cast Object type to String
        pmt.setSequenceEncode(Encode.getEnum(str));

    }//GEN-LAST:event_LANGUAGEActionPerformed

    private void DelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DelActionPerformed
        // TODO add your handling code here:
        int[] rowsSelected = ParamTopList.getSelectedRows();
        AppParmsIni rec = null;
        if ( rowsSelected.length> 0){
            current_row = rowsSelected[0];
            pmt.removeAppParmsIni(current_row);
            model.removeRow(current_row);
            if(current_row>0){
                current_row--;
            }
            gson.GSONsave();
        }
    }//GEN-LAST:event_DelActionPerformed

    private void ProxyScopeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ProxyScopeActionPerformed
        // TODO add your handling code here:
        //ParmGen pg = new ParmGen(pmt);
        if (ProxyScope.isSelected()){
            ParmGen.ProxyInScope = true;
        }else{
            ParmGen.ProxyInScope = false;
        }
    }//GEN-LAST:event_ProxyScopeActionPerformed

    private void IntruderScopeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_IntruderScopeActionPerformed
        // TODO add your handling code here:
        //ParmGen pg = new ParmGen(pmt);
        if (IntruderScope.isSelected()){
            ParmGen.IntruderInScope = true;
        }else{
            ParmGen.IntruderInScope = false;
        }
    }//GEN-LAST:event_IntruderScopeActionPerformed

    private void RepeaterScopeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RepeaterScopeActionPerformed
        // TODO add your handling code here:
        //ParmGen pg = new ParmGen(pmt);
        if (RepeaterScope.isSelected()){
            ParmGen.RepeaterInScope = true;
        }else{
            ParmGen.RepeaterInScope = false;
        }
    }//GEN-LAST:event_RepeaterScopeActionPerformed

    private void ScannerScopeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ScannerScopeActionPerformed
        // TODO add your handling code here:
        //ParmGen pg = new ParmGen(pmt);
        if (ScannerScope.isSelected()){
            ParmGen.ScannerInScope = true;
        }else{
            ParmGen.ScannerInScope = false;
        }
    }//GEN-LAST:event_ScannerScopeActionPerformed

    @SuppressWarnings("rawtypes")
    private void customInitComponents() {

        jLabel1 = new javax.swing.JLabel();
        LANGUAGE = new javax.swing.JComboBox<>();
        Add = new javax.swing.JButton();
        Mod = new javax.swing.JButton();
        Del = new javax.swing.JButton();
        Cancel = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        ParamTopList = new javax.swing.JTable();
        burptoolflg = new javax.swing.JPanel();
        ProxyScope = new javax.swing.JCheckBox();
        IntruderScope = new javax.swing.JCheckBox();
        ScannerScope = new javax.swing.JCheckBox();
        RepeaterScope = new javax.swing.JCheckBox();
        jLabel2 = new javax.swing.JLabel();
        jLabel2.putClientProperty("html.disable", Boolean.FALSE);

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle(bundle.getString("ParmGenTop.PARMGENトップ画面.text")); // NOI18N

        jLabel1.setText(bundle.getString("ParmGenTop.文字コード.text")); // NOI18N

        LANGUAGE.setModel(new javax.swing.DefaultComboBoxModel<String>(new String[] { "SJIS", "EUC-JP", "UTF-8", "ISO8859-1", "x-MacCentralEurope" }));
        LANGUAGE.setToolTipText(bundle.getString("ParmGenTop.文字コード.text")); // NOI18N
        LANGUAGE.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                LANGUAGEActionPerformed(evt);
            }
        });

        Add.setText(bundle.getString("ParmGenTop.新規.text")); // NOI18N
        Add.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AddActionPerformed(evt);
            }
        });

        Mod.setText(bundle.getString("ParmGenTop.修正.text")); // NOI18N
        Mod.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ModActionPerformed(evt);
            }
        });

        Del.setText(bundle.getString("ParmGenTop.削除.text")); // NOI18N
        Del.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DelActionPerformed(evt);
            }
        });

        Cancel.setText(bundle.getString("ParmGenTop.閉じる.text")); // NOI18N
        Cancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CancelActionPerformed(evt);
            }
        });

        ParamTopList.setModel(new javax.swing.table.DefaultTableModel(
                new Object [][] {
                        {null, null, ".*/input.php.*", null, null, null, null, null},
                        {null, null, null, null, null, null, null, null},
                        {null, null, null, null, null, null, null, null},
                        {null, null, null, null, null, null, null, null}
                },
                new String [] {
                        "", "FromTo", "", "初期値/CSVファイル", "桁数", "", "パターンリスト", "現在値"
                }
        ) {
            Class[] types = new Class [] {
                    java.lang.Boolean.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.Integer.class, java.lang.String.class, java.lang.String.class, java.lang.String.class
            };
            boolean[] canEdit = new boolean [] {
                    true, false, false, false, false, false, false, false
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        ParamTopList.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        ParamTopList.setRowHeight(18);
        ParamTopList.getTableHeader().setReorderingAllowed(false);
        jScrollPane1.setViewportView(ParamTopList);
        if (ParamTopList.getColumnModel().getColumnCount() > 0) {
            ParamTopList.getColumnModel().getColumn(0).setPreferredWidth(35);
            ParamTopList.getColumnModel().getColumn(0).setHeaderValue(bundle.getString("ParmGenTop.title0.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(2).setPreferredWidth(200);
            ParamTopList.getColumnModel().getColumn(2).setHeaderValue(bundle.getString("ParmGenTop.title1.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(3).setPreferredWidth(150);
            ParamTopList.getColumnModel().getColumn(3).setHeaderValue(bundle.getString("ParmGenTop.title2.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(4).setPreferredWidth(40);
            ParamTopList.getColumnModel().getColumn(4).setHeaderValue(bundle.getString("ParmGenTop.title3.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(5).setPreferredWidth(70);
            ParamTopList.getColumnModel().getColumn(5).setHeaderValue(bundle.getString("ParmGenTop.title4.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(6).setPreferredWidth(200);
            ParamTopList.getColumnModel().getColumn(6).setHeaderValue(bundle.getString("ParmGenTop.title5.text")); // NOI18N
            ParamTopList.getColumnModel().getColumn(7).setHeaderValue(bundle.getString("ParmGenTop.title6.text")); // NOI18N
        }

        burptoolflg.setBorder(javax.swing.BorderFactory.createTitledBorder(bundle.getString("ParmGenTop.typeoftool.text"))); // NOI18N

        ProxyScope.setText(bundle.getString("ParmGenTop.PROXY.text")); // NOI18N
        ProxyScope.setEnabled(false);
        ProxyScope.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ProxyScopeActionPerformed(evt);
            }
        });

        IntruderScope.setSelected(true);
        IntruderScope.setText(bundle.getString("ParmGenTop.INTRUDER.text")); // NOI18N
        IntruderScope.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                IntruderScopeActionPerformed(evt);
            }
        });

        ScannerScope.setSelected(true);
        ScannerScope.setText(bundle.getString("ParmGenTop.SCANNER.text")); // NOI18N
        ScannerScope.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ScannerScopeActionPerformed(evt);
            }
        });

        RepeaterScope.setSelected(true);
        RepeaterScope.setText(bundle.getString("ParmGenTop.REPEATER.text")); // NOI18N
        RepeaterScope.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RepeaterScopeActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout burptoolflgLayout = new javax.swing.GroupLayout(burptoolflg);
        burptoolflg.setLayout(burptoolflgLayout);
        burptoolflgLayout.setHorizontalGroup(
                burptoolflgLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(burptoolflgLayout.createSequentialGroup()
                                .addContainerGap()
                                .addComponent(ProxyScope)
                                .addGap(18, 18, 18)
                                .addComponent(IntruderScope)
                                .addGap(32, 32, 32)
                                .addComponent(RepeaterScope)
                                .addGap(34, 34, 34)
                                .addComponent(ScannerScope)
                                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        burptoolflgLayout.setVerticalGroup(
                burptoolflgLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(burptoolflgLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(ProxyScope)
                                .addComponent(IntruderScope)
                                .addComponent(ScannerScope)
                                .addComponent(RepeaterScope))
        );

        jLabel2.setText(bundle.getString("ParmGenTop.注意：処理実行前に、この画面は保存または閉じるボタンで閉じてください。.text")); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addGap(25, 25, 25)
                                                .addComponent(Add)
                                                .addGap(66, 66, 66)
                                                .addComponent(Mod)
                                                .addGap(66, 66, 66)
                                                .addComponent(Del)
                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                .addComponent(Cancel))
                                        .addGroup(layout.createSequentialGroup()
                                                .addContainerGap()
                                                .addComponent(jLabel1)
                                                .addGap(18, 18, 18)
                                                .addComponent(LANGUAGE, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addGap(40, 40, 40)
                                                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 472, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                .addGap(0, 146, Short.MAX_VALUE))
                                        .addGroup(layout.createSequentialGroup()
                                                .addContainerGap()
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(burptoolflg, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                        .addComponent(jScrollPane1))))
                                .addContainerGap())
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(LANGUAGE, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabel1)
                                        .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 43, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addComponent(burptoolflg, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(Add)
                                        .addComponent(Mod)
                                        .addComponent(Del)
                                        .addComponent(Cancel))
                                .addGap(28, 28, 28))
        );

        pack();
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton Add;
    private javax.swing.JButton Cancel;
    private javax.swing.JButton Del;
    private javax.swing.JCheckBox IntruderScope;
    private javax.swing.JComboBox<String> LANGUAGE;
    private javax.swing.JButton Mod;
    private javax.swing.JTable ParamTopList;
    private javax.swing.JCheckBox ProxyScope;
    private javax.swing.JCheckBox RepeaterScope;
    private javax.swing.JCheckBox ScannerScope;
    private javax.swing.JPanel burptoolflg;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration//GEN-END:variables
}
