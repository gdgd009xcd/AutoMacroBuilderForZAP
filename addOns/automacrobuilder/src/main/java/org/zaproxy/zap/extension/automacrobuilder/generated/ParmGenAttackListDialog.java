/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.List;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListModel;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.ListModel;
import org.zaproxy.zap.extension.automacrobuilder.ParmFileFilter;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenReadFile;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenWriteFile;
import org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables;

/**
 *
 * @author gdgd009xcd
 */
@Deprecated
@SuppressWarnings("serial")
public class ParmGenAttackListDialog extends javax.swing.JDialog {

    private ParmGenNew parentwin;
//    private java.awt.Frame parentwin;
    private String defaultAtkListFileName = "AttackList.txt";
    private String currentAtkListFile ;
    private DefaultListModel<String> PatternModel;
    
    /**
     * Creates new form ParmGenAttackListDialog
     */
    public ParmGenAttackListDialog(ParmGenNew parent, boolean modal, String currentFile) {
        super(parent, modal);
        initComponents();
        //パターンリストのモデルをDefaultListModelに置き換える。
        ListModel<String> m = PatternList.getModel();
        PatternModel = new DefaultListModel<>();
        for(int i = 0; i < m.getSize(); i++){
            String d = m.getElementAt(i);
            PatternModel.addElement(d);
        }
        PatternList.setModel(PatternModel);
        parentwin = parent;
        if(currentFile != null && !currentFile.isEmpty()){
            currentAtkListFile = currentFile;
        }else{
            currentAtkListFile = EnvironmentVariables.projectdir + "\\" + defaultAtkListFileName;
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings({"unchecked","rawtypes","serial"})
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        PatternList = new javax.swing.JList<>();
        AttackList = new javax.swing.JComboBox<>();
        jLabel1 = new javax.swing.JLabel();
        Load = new javax.swing.JButton();
        PatternEditor = new javax.swing.JTextField();
        jButton1 = new javax.swing.JButton();
        Delete = new javax.swing.JButton();
        Save = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        OK = new javax.swing.JButton();
        Cancel = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        StartAdvance = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        PatternList.setModel(new javax.swing.AbstractListModel<String>() {
            String[] strings = { "'", "%0a", "'||'", "'|'", "/**/", "/*/", "-0", "-", " and 1%3D1 ", " bnd 1%3D1 ", "%09and%091%3D1%09", "%09bnd%091%3D1%09", "; select pg_sleep(120); -- ", "'; select pg_sleep(120); -- ", " " };
            public int getSize() { return strings.length; }
            public String getElementAt(int i) { return strings[i]; }
        });
        PatternList.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        PatternList.addListSelectionListener(new javax.swing.event.ListSelectionListener() {
            public void valueChanged(javax.swing.event.ListSelectionEvent evt) {
                PatternListValueChanged(evt);
            }
        });
        jScrollPane1.setViewportView(PatternList);

        AttackList.setEditable(true);
        AttackList.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "C:\\Users\\xxxx\\Desktop\\ParmGenParms\\SQL Injection.txt", "C:\\Users\\xxxx\\Desktop\\ParmGenParms\\XSS.txt", "C:\\Users\\xxxxx\\Desktop\\ParmGenParms\\HTTP Response Divide.txt", "C:\\Users\\xxxxx\\Desktop\\ParmGenParms\\OS command injection.txt" }));

        jLabel1.setText("Attack Pattern List");

        Load.setText("Load");
        Load.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                LoadActionPerformed(evt);
            }
        });

        PatternEditor.setText("jTextField2");

        jButton1.setText("Add/Updt");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        Delete.setText("Delete");
        Delete.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DeleteActionPerformed(evt);
            }
        });

        Save.setText("Save");
        Save.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SaveActionPerformed(evt);
            }
        });

        OK.setText("OK");
        OK.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                OKActionPerformed(evt);
            }
        });

        Cancel.setText("Cancel");
        Cancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CancelActionPerformed(evt);
            }
        });

        jLabel2.setText("開始位置");

        StartAdvance.setText("0");
        StartAdvance.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                StartAdvanceActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jSeparator1)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 196, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                .addGroup(layout.createSequentialGroup()
                                    .addComponent(OK)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(Cancel))
                                .addGroup(layout.createSequentialGroup()
                                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(AttackList, javax.swing.GroupLayout.PREFERRED_SIZE, 388, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 388, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGroup(layout.createSequentialGroup()
                                            .addComponent(jButton1)
                                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                            .addComponent(PatternEditor)))
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(Load, javax.swing.GroupLayout.PREFERRED_SIZE, 104, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(Save, javax.swing.GroupLayout.PREFERRED_SIZE, 104, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(Delete, javax.swing.GroupLayout.PREFERRED_SIZE, 104, javax.swing.GroupLayout.PREFERRED_SIZE))))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel2)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(StartAdvance, javax.swing.GroupLayout.PREFERRED_SIZE, 86, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(StartAdvance, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(15, 15, 15)
                .addComponent(AttackList, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(Load)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(Save)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(Delete)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton1)
                    .addComponent(PatternEditor, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 2, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(OK)
                    .addComponent(Cancel))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void CancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CancelActionPerformed
        // TODO add your handling code here:
        dispose();
    }//GEN-LAST:event_CancelActionPerformed

    private void OKActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_OKActionPerformed
        // TODO add your handling code here:
        DefaultComboBoxModel<String> cmodel = (DefaultComboBoxModel<String>)AttackList.getModel();
        String selectedPattern = (String)cmodel.getSelectedItem();
        parentwin.setPatternFileName(selectedPattern);
    }//GEN-LAST:event_OKActionPerformed

    private void PatternListValueChanged(javax.swing.event.ListSelectionEvent evt) {//GEN-FIRST:event_PatternListValueChanged
        // TODO add your handling code here:
        String result = "";
        List<String> alist = PatternList.getSelectedValuesList();
        //Object[] arr = PatternList.getSelectedValues(); // java v1.7 obsolete
        //for(Object obj:arr){
        //  result = (String)obj;//最後の選択
        //}
        for(String data:alist){
            result = data;//最後の選択
        }
        PatternEditor.setText(result);       
    }//GEN-LAST:event_PatternListValueChanged

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        // TODO add your handling code here:
        String pattern = PatternEditor.getText();
        int sidx = PatternList.getSelectedIndex();
        PatternModel.insertElementAt(pattern, sidx);
        int maxidx = PatternModel.getSize();
        if(sidx+2 < maxidx){
            PatternModel.remove(sidx+1);
        }
        
    }//GEN-LAST:event_jButton1ActionPerformed

    private void DeleteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DeleteActionPerformed
        // TODO add your handling code here:
        int sidx = PatternList.getSelectedIndex();
        int maxidx = PatternModel.getSize();
        if(sidx>=0&& sidx+1 < maxidx){
            PatternModel.remove(sidx);
        }
    }//GEN-LAST:event_DeleteActionPerformed

    private void LoadActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_LoadActionPerformed
        // TODO add your handling code here:
        File cfile = new File(currentAtkListFile);
        String dirname = cfile.getParent();
        JFileChooser jfc = new JFileChooser(dirname);
        jfc.setSelectedFile(cfile);
        ParmFileFilter pFilter=new ParmFileFilter();
        jfc.setFileFilter(pFilter);
        if(jfc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) { 
            //code to handle choosed file here. 
            File file = jfc.getSelectedFile();
            String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");
            currentAtkListFile = name;
            AttackList.removeItem((Object)currentAtkListFile);
            AttackList.addItem(currentAtkListFile);
            //追加した項目を選択
            DefaultComboBoxModel<String> cmodel = (DefaultComboBoxModel<String>)AttackList.getModel();
            int lastidx = cmodel.getSize()-1;
            if(lastidx>=0){
                Object sobj = cmodel.getElementAt(lastidx);
                cmodel.setSelectedItem(sobj);
            }
            //ファイルをPatternListに設定
            try {
                ParmGenReadFile rfile = new ParmGenReadFile(currentAtkListFile);
                String rec;
                PatternModel.clear();
                while((rec=rfile.read())!=null){
                    PatternModel.addElement(rec);
                }
                PatternModel.addElement(" ");
                rfile.close();
            } catch (FileNotFoundException ex) {
                EnvironmentVariables.plog.printException(ex);
                JOptionPane.showMessageDialog(this,"パターンファイル読み込みエラー\n"+ ex.toString() ,  "パターンファイルエラー", JOptionPane.ERROR_MESSAGE);
            }
            
            
        }
    }//GEN-LAST:event_LoadActionPerformed

    private void SaveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SaveActionPerformed
        // TODO add your handling code here:
        File cfile = new File(currentAtkListFile);
        String dirname = cfile.getParent();
        JFileChooser jfc = new JFileChooser(dirname);
        jfc.setSelectedFile(cfile);
        ParmFileFilter pFilter=new ParmFileFilter();
        jfc.setFileFilter(pFilter);
        if(jfc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) { 
            //code to handle choosed file here. 
            File file = jfc.getSelectedFile();
            String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");
            currentAtkListFile = name;
            try{
                ParmGenWriteFile wfile = new ParmGenWriteFile(currentAtkListFile);
                Object o;
                int imax = PatternModel.getSize();
                for(int i = 0; i< imax-1; i++){
                    o = PatternModel.getElementAt(i);
                    wfile.print((String)o);
                }
                wfile.close();
            }catch(Exception ex){
                EnvironmentVariables.plog.printException(ex);
                JOptionPane.showMessageDialog(this,"パターンファイル書き込みエラー\n"+ ex.toString() ,  "パターンファイルエラー", JOptionPane.ERROR_MESSAGE);
            }
            
        } 
    }//GEN-LAST:event_SaveActionPerformed

    private void StartAdvanceActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_StartAdvanceActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_StartAdvanceActionPerformed

    

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JComboBox<String> AttackList;
    private javax.swing.JButton Cancel;
    private javax.swing.JButton Delete;
    private javax.swing.JButton Load;
    private javax.swing.JButton OK;
    private javax.swing.JTextField PatternEditor;
    private javax.swing.JList<String> PatternList;
    private javax.swing.JButton Save;
    private javax.swing.JTextField StartAdvance;
    private javax.swing.JButton jButton1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JSeparator jSeparator1;
    // End of variables declaration//GEN-END:variables
}
