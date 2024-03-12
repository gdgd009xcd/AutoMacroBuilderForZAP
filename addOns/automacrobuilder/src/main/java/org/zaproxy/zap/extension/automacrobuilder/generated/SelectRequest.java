/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.util.ArrayList;
import java.util.ResourceBundle;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

import org.zaproxy.zap.extension.automacrobuilder.PRequest;
import org.zaproxy.zap.extension.automacrobuilder.PRequestResponse;
import org.zaproxy.zap.extension.automacrobuilder.PResponse;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenGSONSaveV2;
import org.zaproxy.zap.extension.automacrobuilder.view.JTextPaneContents;
import org.zaproxy.zap.extension.automacrobuilder.interfaceParmGenWin;

/**
 *
 * @author gdgd009xcd
 */
@SuppressWarnings("serial")
public class SelectRequest extends javax.swing.JDialog {

    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

       DefaultTableModel model;
       interfaceParmGenWin pgenwin;
       ArrayList<PRequestResponse> P_proxy_messages;
       int selected_message_idx;
       int panelno;
       interfaceParmGenWin nextwin;
       
    /**
     * Creates new form SelectRequest
     */
    public SelectRequest(String title, interfaceParmGenWin _pgenwin, interfaceParmGenWin _nextwin, int _panelno) {
        pgenwin = _pgenwin;
        panelno = _panelno;
        nextwin = _nextwin;
        setRequest(ParmGenGSONSaveV2.proxy_messages);
        initComponents();
        setTitle(title);
        TableColumn col ;
        int[] colsize = {
            60, 250, 60
        };
        for(int i=0; i<3; i++){
            col= RequestTable.getColumnModel().getColumn(i);
            col.setPreferredWidth(colsize[i]);
        }
        this.setModal(true);
        switch(_panelno){
            case ParmGenNew.P_RESPONSETAB:
                selected_message_idx = 0;
                break;
            default:
                int size = RequestTable.getRowCount();
                if(size<=0){
                    size = 0;
                }else{
                    size--;
                }
                selected_message_idx = size;
                break;
        }
        RequestTable.setRowSelectionInterval(selected_message_idx, selected_message_idx);
        SwingUtilities.invokeLater(() -> {
            RequestTableMouseClicked(null);
        });
        

    }

    /**
     * add element of proxy_message to TableModel
     *
     * @param proxy_messages
     */
    public void setRequest(ArrayList <PRequestResponse> proxy_messages){
        
        model = new DefaultTableModel();

        P_proxy_messages = proxy_messages;

        // Create a couple of columns
        model.addColumn(bundle.getString("SelectRequest.METHOD.text"));
        model.addColumn(bundle.getString("SelectRequest.URL.text"));
        model.addColumn(bundle.getString("SelectRequest.STATUS.text"));
        
        if ( proxy_messages != null){
            for(int i=0; i< proxy_messages.size();i++){
                PRequest _request = proxy_messages.get(i).request;
                PResponse _response = proxy_messages.get(i).response;
                String method = _request.getMethod();
                String url = _request.getURL();
                String status = _response.getStatus();

                model.addRow(new Object[]{method, url, status});
            }
        }
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        RequestTable = new javax.swing.JTable();
        MessageSelected = new javax.swing.JButton();
        jButton2 = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanel1 = new javax.swing.JPanel();
        jScrollPane6 = new javax.swing.JScrollPane();
        RequestEntity = new javax.swing.JTextPane();
        jPanel2 = new javax.swing.JPanel();
        jScrollPane4 = new javax.swing.JScrollPane();
        ResponseEntity = new javax.swing.JTextPane();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle(bundle.getString("SelectRequest.SelectTitle.text")); // NOI18N

        RequestTable.setModel(model);
        RequestTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        RequestTable.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                RequestTableMouseClicked(evt);
            }
        });
        jScrollPane1.setViewportView(RequestTable);

        MessageSelected.setText(bundle.getString("SelectRequest.OK.text")); // NOI18N
        MessageSelected.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                MessageSelectedActionPerformed(evt);
            }
        });

        jButton2.setText(bundle.getString("SelectRequest.Cancel.text")); // NOI18N
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jLabel1.setText(bundle.getString("SelectRequest.InstructionDescLabel1.text")); // NOI18N

        RequestEntity.setText("GET /index.php?DB=1 HTTP/1.1\nHost: glide\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\nAccept-Language: ja,en-US;q=0.7,en;q=0.3\nAccept-Encoding: gzip, deflate\nConnection: close\nUpgrade-Insecure-Requests: 1\nContent-Length: 0\n");
        jScrollPane6.setViewportView(RequestEntity);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 449, Short.MAX_VALUE)
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 216, Short.MAX_VALUE)
        );

        jTabbedPane1.addTab(bundle.getString("SelectRequest.REQUEST.text"), jPanel1); // NOI18N

        jScrollPane4.setViewportView(ResponseEntity);

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 449, Short.MAX_VALUE)
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, 216, Short.MAX_VALUE)
        );

        jTabbedPane1.addTab(bundle.getString("SelectRequest.RESPONSE.text"), jPanel2); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(14, 14, 14)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jTabbedPane1)
                            .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 310, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jScrollPane1))
                        .addGap(14, 14, 14))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(MessageSelected)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jButton2)
                        .addContainerGap())))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 21, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 130, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addComponent(jTabbedPane1)
                .addGap(10, 10, 10)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(MessageSelected)
                    .addComponent(jButton2))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void MessageSelectedActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_MessageSelectedActionPerformed
        // TODO add your handling code here:
        // update selected message
        ParmGenGSONSaveV2.selected_messages.clear();
        ParmGenGSONSaveV2.selected_messages.add(ParmGenGSONSaveV2.proxy_messages.get(selected_message_idx));
        pgenwin.updateMessageAreaInSelectedModel(panelno);
        dispose();
        if(nextwin!=null){
            nextwin.update();
            nextwin.setVisible(true);
        }
    }//GEN-LAST:event_MessageSelectedActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        // TODO add your handling code here:
       dispose();
          
    }//GEN-LAST:event_jButton2ActionPerformed

    private void RequestTableMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_RequestTableMouseClicked
        // TODO add your handling code here:
        //Point point = evt.getPoint();
        //int row = RequestTable.rowAtPoint(point);
        //int column = RequestTable.columnAtPoint(point);
        //int[] sidx = RequestTable.getSelectedRows();
        int sidx = RequestTable.getSelectedRow();

        PRequest request = null;
        PResponse response = null;
        if ( sidx >= 0){
            request = P_proxy_messages.get(sidx).request;
            response = P_proxy_messages.get(sidx).response;
            selected_message_idx = sidx;
        }

        JTextPaneContents reqdoc = new JTextPaneContents(RequestEntity);
        JTextPaneContents resdoc = new JTextPaneContents(ResponseEntity);

        reqdoc.setRequestChunks(request);
        resdoc.setResponseChunks(response);

        RequestEntity.setCaretPosition(0);
        ResponseEntity.setCaretPosition(0);
    }//GEN-LAST:event_RequestTableMouseClicked

    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton MessageSelected;
    private javax.swing.JTextPane RequestEntity;
    private javax.swing.JTable RequestTable;
    private javax.swing.JTextPane ResponseEntity;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JTabbedPane jTabbedPane1;
    // End of variables declaration//GEN-END:variables
}
