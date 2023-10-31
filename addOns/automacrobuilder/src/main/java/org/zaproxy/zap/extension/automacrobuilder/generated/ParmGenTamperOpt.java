/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.util.ResourceBundle;
import org.zaproxy.zap.extension.automacrobuilder.AppValue;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenSession;
import org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables;
import org.zaproxy.zap.extension.automacrobuilder.interfaceParmGenWin;


/**
 *
 * @author gdgd009xcd
 */
@SuppressWarnings("serial")
public class ParmGenTamperOpt extends javax.swing.JDialog implements interfaceParmGenWin {
    ParmGenNew parentwin;
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");
    
    /**
     * Creates new form ParmGenTamperOpt
     */
    public ParmGenTamperOpt(ParmGenNew _parentwin) {
        super(_parentwin, true);
        parentwin = _parentwin;
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings({"unchecked","rawtypes","serial"})
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        PayloadPosition = new javax.swing.JComboBox<>();
        jLabel2 = new javax.swing.JLabel();
        TargetParam = new javax.swing.JComboBox<>();
        jSeparator1 = new javax.swing.JSeparator();
        OK = new javax.swing.JToggleButton();
        CANCEL = new javax.swing.JToggleButton();
        jLabel3 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        jLabel1.setText(bundle.getString("ParmGenTamperOpt.jLabel1.text")); // NOI18N

        PayloadPosition.setModel(new javax.swing.DefaultComboBoxModel(AppValue.makePayloadPositionNames()));
        PayloadPosition.setToolTipText(bundle.getString("ParmGenTamperOpt.PayloadPosition.toolTipText")); // NOI18N
        PayloadPosition.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                PayloadPositionActionPerformed(evt);
            }
        });

        jLabel2.setText(bundle.getString("ParmGenTamperOpt.jLabel2.text")); // NOI18N

        TargetParam.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "GET", "POST", "GET/POST", " " }));

        OK.setText(bundle.getString("ParmGenTamperOpt.OK.text")); // NOI18N
        OK.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                OKActionPerformed(evt);
            }
        });

        CANCEL.setText(bundle.getString("ParmGenTamperOpt.CANCEL.text")); // NOI18N
        CANCEL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CANCELActionPerformed(evt);
            }
        });

        jLabel3.setText(bundle.getString("ParmGenTamperOpt.jLabel3.text")); // NOI18N
        jLabel3.setVerticalAlignment(javax.swing.SwingConstants.TOP);
        jLabel3.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(0, 0, 0)));

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jSeparator1)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 121, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(PayloadPosition, javax.swing.GroupLayout.PREFERRED_SIZE, 64, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 121, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(TargetParam, javax.swing.GroupLayout.PREFERRED_SIZE, 179, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(8, 8, 8)
                                .addComponent(OK, javax.swing.GroupLayout.PREFERRED_SIZE, 74, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(CANCEL)
                                .addGap(10, 10, 10))))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(20, 20, 20)
                        .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 86, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(TargetParam, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(PayloadPosition, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(OK)
                    .addComponent(CANCEL))
                .addGap(27, 27, 27))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void CANCELActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CANCELActionPerformed
        // TODO add your handling code here:
        dispose();
    }//GEN-LAST:event_CANCELActionPerformed

    private void OKActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_OKActionPerformed
        // TODO add your handling code here:
        dispose();
        //TargetParam 診断対象パラメータ
        EnvironmentVariables.session.put(ParmGenSession.K_TARGETPARAM, (String) TargetParam.getSelectedItem());
        //PayloadPosition パターン埋め込み位置
        EnvironmentVariables.session.put(ParmGenSession.K_PAYLOADPOSITION, (String) PayloadPosition.getSelectedItem());
        new ParmGenAddParms(parentwin, false).setVisible(true);
    }//GEN-LAST:event_OKActionPerformed

    private void PayloadPositionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_PayloadPositionActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_PayloadPositionActionPerformed

    

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JToggleButton CANCEL;
    private javax.swing.JToggleButton OK;
    private javax.swing.JComboBox<String> PayloadPosition;
    private javax.swing.JComboBox<String> TargetParam;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JSeparator jSeparator1;
    // End of variables declaration//GEN-END:variables

    @Override
    public void updateMessageAreaInSelectedModel(int panel) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public void update() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
