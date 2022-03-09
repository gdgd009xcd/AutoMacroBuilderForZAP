/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.DefaultComboBoxModel;

import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableModel;

import org.zaproxy.zap.extension.automacrobuilder.*;

/**
 *
 * @author tms783
 */
@SuppressWarnings("serial")
public class ParmGenAddParms extends javax.swing.JDialog implements interfaceParmGenWin {

    //起動元ウィンドウ
    ParmGenNew parentwin;
    PRequest selected_request;
    DefaultTableModel ReqParsedTableModel;
    boolean wholeval;// == true 全体を置き換える == false 数値のみ置き換える
    boolean isformdata;// == true form-data == false www-url-encoded
    public static final int VT_DEFAULT=0;
    public static final int VT_NUMBERFIXED=1;
    public static final int VT_ALPHANUMFIXED = 2;
    public static final int VT_NUMBER=3;
    public static final int VT_ALPHANUM=4;
    public static final int VT_FIXED = 5;
    public static final int VT_PARAMVALUE = 6;
    public static final int VT_NUMCOUNTER = 7;
    public static final int VT_VALUE = 8;
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");
    private static  DefaultComboBoxModel<String> comboModel = null;
    private int[] ListSelectionModel;


    /**
     * Creates new form ParmGenAddParms
     */
    public ParmGenAddParms(ParmGenNew _parentwin,  boolean _wholeval) {
        parentwin = _parentwin;
        isformdata = false;
        wholeval = _wholeval;
        if(comboModel==null){
            comboModel = new javax.swing.DefaultComboBoxModel<>(new String[] { bundle.getString("ParmGenAddParms.comboModel.デフォルト.text"), bundle.getString("ParmGenAddParms.comboModel.数値固定長.text"), bundle.getString("ParmGenAddParms.comboModel.英数字固定長.text"), bundle.getString("ParmGenAddParms.comboModel.数値任意長.text"), bundle.getString("ParmGenAddParms.comboModel.英数字任意長.text"), bundle.getString("ParmGenAddParms.comboModel.固定値.text") });
        }
        initComponents();
        this.setModal(true);
        update();

    }

    private void deleteRows(){
        for( int i = ReqParsedTableModel.getRowCount() - 1; i >= 0; i-- ){
            ReqParsedTableModel.removeRow(i);
        }
    }


    public void update(){
        ReqParsedTableModel = (DefaultTableModel)ReqParsedTable.getModel();
        Select_ReplaceTargetURL.removeAllItems();
        PRequestResponse selected_message = ParmGenGSONSave.selected_messages.get(0);
        int mpos = selected_message.getMacroPos();
        if(mpos<0){
            mpos = ParmVars.TOSTEPANY;
        }
        ParmVars.session.put(ParmGenSession.K_TOPOS, Integer.toString(mpos));
        selected_request = selected_message.request;
        String newtargetURL = ".*" + selected_request.getPath() + ".*";
        Select_ReplaceTargetURL.addItem(newtargetURL);
        String currenturl = parentwin.getTargetURL();
        if ( currenturl != null && !currenturl.isEmpty()){
            if(currenturl.indexOf(newtargetURL)==-1){//newtargetURLが部分一致しない
                Select_ReplaceTargetURL.addItem(currenturl);
                Select_ReplaceTargetURL.addItem(currenturl + "|.*" + selected_request.getPath() + ".*");
            }
        }
        deleteRows();

        AppValue ap = new AppValue();

        //path全体
        String wholepath = selected_request.getURL();
        ReqParsedTableModel.addRow(new Object[]{ap.getValPart(AppValue.V_PATH), Integer.toString(0), wholepath});

        Iterator<String> pit = selected_request.pathparams.iterator();
        int ppos = 1;
        while(pit.hasNext()){
            ReqParsedTableModel.addRow(new Object[]{ap.getValPart(AppValue.V_PATH), Integer.toString(ppos), pit.next()});
            ppos++;
        }

        Iterator<String[]> it = selected_request.getQueryParams().iterator();
        int rcnt = 0;
        while(it.hasNext()){
            rcnt++;
            String[] nv = it.next();
            ReqParsedTableModel.addRow(new Object[]{"query", nv[0], nv[1]});
        }
        Iterator<String[]> itb = selected_request.getBodyParams().iterator();

        while(itb.hasNext()){
            rcnt++;
            String[] nv = itb.next();
            if(selected_request.isFormData()){
                ReqParsedTableModel.addRow(new Object[]{"formdata", nv[0], nv[1]});
            }else{
                ReqParsedTableModel.addRow(new Object[]{"body", nv[0], nv[1]});
            }
        }
        
        //JSON request
        ParmGenGSONDecoder reqjdecoder = new ParmGenGSONDecoder(selected_request.getBodyStringWithoutHeader());
        List<ParmGenToken> reqjtklist = reqjdecoder.parseJSON2Token();
        for(ParmGenToken tk: reqjtklist){
            rcnt++;
            String name = tk.getTokenKey().getName();
            String value = tk.getTokenValue().getValue();
            ReqParsedTableModel.addRow(new Object[]{"json", name, value});
        }
        
        if (rcnt<=0){
            ReqParsedTableModel.addRow(new Object[]{"body", "null", "null"});
        }

        //クッキー一覧
        Iterator<String[]> cit = selected_request.cookieparams.iterator();
        while(cit.hasNext()){
            String[] nv = cit.next();
            ReqParsedTableModel.addRow(new Object[]{"cookie", nv[0], nv[1]});
        }

        //リクエストヘッダー覧
        ArrayList<String[]> hlist = selected_request.getHeaders();
        Iterator<String[]> hit = hlist.iterator();
        while(hit.hasNext()){
            String[] nv = hit.next();
            if(nv.length>1){
                if(!nv[0].matches("[Cc]ookie")){
                    ReqParsedTableModel.addRow(new Object[]{"header", nv[0], nv[1]});
                }
            }

        }
        int i = 0;
        if(wholeval){
            i = 1;//全体
        }
        ValReplacePart.setSelectedItem(i);
        if(selected_request.isFormData()){
            isformdata = true;
        }

        //パラメータを選択
        //追跡パラメータの一覧を取得
        int j = 0;
        ArrayList<String> names = new ArrayList<>();

        for(j=0; j<1000; j++){
            String n = ParmVars.session.get(j, ParmGenSession.K_TOKEN);
            if(n==null)break;
            names.add(n);
        }

        //追跡パラメータ名,診断対象タイプに一致するテーブルのインデクスを選択

        //診断対象タイプ
        String targetparam = ParmVars.session.get(ParmGenSession.K_TARGETPARAM);
        int targetpflag = 0;
        if(targetparam != null){
            if(targetparam.equals("GET")){
                targetpflag = 1;
            }else if(targetparam.equals("POST")){
                targetpflag = 2;
            }else if(targetparam.equals("GET/POST")){
                targetpflag = 3;
            }
        }
        int rmax = ReqParsedTableModel.getRowCount();
        ListSelectionModel lmodel = ReqParsedTable.getSelectionModel();
        for(j=0; j<rmax;j++){
            String targetptype = (String)ReqParsedTableModel.getValueAt(j, 0);//type
            String name = (String)ReqParsedTableModel.getValueAt(j, 1);//name
            String namedecoded = name;
            try {
                namedecoded = URLDecoder.decode(name, ParmVars.enc.getIANACharsetName());
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(ParmGenAddParms.class.getName()).log(Level.SEVERE, null, ex);
            }
            if(names.contains(namedecoded)){//一致したパラメータを選択
                lmodel.addSelectionInterval(j, j);
            }else if(!namedecoded.equals("null")){
                switch(targetpflag){
                    case 1://GET(query)
                        if(targetptype.equals("query")){
                            lmodel.addSelectionInterval(j, j);
                        }
                        break;
                    case 2://POST(body, formdata)
                        if(targetptype.equals("body")||targetptype.equals("formdata")){
                            lmodel.addSelectionInterval(j, j);
                        }
                        break;
                    case 3://GET/POST (query, body, formdata)
                        if(targetptype.equals("body")||targetptype.equals("formdata")||targetptype.equals("query")){
                            lmodel.addSelectionInterval(j, j);
                        }
                        break;
                    default:
                        break;
                }
            }
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

        jLabel5 = new javax.swing.JLabel();
        jScrollPane8 = new javax.swing.JScrollPane();
        ReqParsedTable = new javax.swing.JTable();
        Add = new javax.swing.JButton();
        Cancel = new javax.swing.JButton();
        Select_ReplaceTargetURL = new javax.swing.JComboBox<>();
        jLabel1 = new javax.swing.JLabel();
        jPanel1 = new javax.swing.JPanel();
        ValReplacePart = new javax.swing.JComboBox<>();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle(bundle.getString("ParmGenAddParms.パラメータ選択画面.text")); // NOI18N

        jLabel5.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel5.setText(bundle.getString("ParmGenAddParms.jLabel5.text")); // NOI18N
        jLabel5.setVerticalAlignment(javax.swing.SwingConstants.TOP);

        ReqParsedTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {"path", "", "/input.php"},
                {"query", "search", "aiueo"},
                {"body", "name", "chikara"},
                {"body", "password", "secret"},
                {"body", "", null},
                {"body", null, null}
            },
            new String [] {
                "位置", "parameter", "value"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.String.class, java.lang.String.class, java.lang.String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        ReqParsedTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        ReqParsedTable.getTableHeader().setReorderingAllowed(false);
        jScrollPane8.setViewportView(ReqParsedTable);
        if (ReqParsedTable.getColumnModel().getColumnCount() > 0) {
            ReqParsedTable.getColumnModel().getColumn(0).setHeaderValue(bundle.getString("ParmGenAddParms.position.text")); // NOI18N
        }

        Add.setText(bundle.getString("ParmGenAddParms.追加.text")); // NOI18N
        Add.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AddActionPerformed(evt);
            }
        });

        Cancel.setText(bundle.getString("ParmGenAddParms.取消.text")); // NOI18N
        Cancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CancelActionPerformed(evt);
            }
        });

        Select_ReplaceTargetURL.setEditable(true);
        Select_ReplaceTargetURL.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));
        Select_ReplaceTargetURL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Select_ReplaceTargetURLActionPerformed(evt);
            }
        });

        jLabel1.setText(bundle.getString("ParmGenAddParms.置換対象パス：　既設定値に戻す場合は、下記のプルダウンで選択.text")); // NOI18N

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder(bundle.getString("ParmGenAddParms.jPanel1.border.text"))); // NOI18N

        ValReplacePart.setModel(comboModel);
        ValReplacePart.setToolTipText(bundle.getString("ParmGenAddParms.numbertooltip.text")); // NOI18N
        ValReplacePart.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ValReplacePartActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(ValReplacePart, 0, 140, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(ValReplacePart, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 10, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(Select_ReplaceTargetURL, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(Add)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(Cancel))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 247, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(12, 12, 12))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane8, javax.swing.GroupLayout.DEFAULT_SIZE, 474, Short.MAX_VALUE)
                        .addContainerGap())))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(Select_ReplaceTargetURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel5)
                    .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(jScrollPane8, javax.swing.GroupLayout.DEFAULT_SIZE, 105, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(Add)
                    .addComponent(Cancel))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void CancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CancelActionPerformed
        // TODO add your handling code here:
        dispose();
    }//GEN-LAST:event_CancelActionPerformed


    

    private String getValueRegex(String v, boolean ispath, boolean iscookie, boolean isheader, boolean isjson, boolean iswholepath){
        wholeval = false;
        boolean fixed = true;
        String regpattern = "";
        String prepostpattern = "";
        int vlen = v.length();
        String vreg = ".{" + vlen + "}";
        
        int selidx = ValReplacePart.getSelectedIndex();
        if(selidx==VT_DEFAULT){
            switch(parentwin.getCurrentModel()){
                    
                case ParmGenNew.P_NUMBERMODEL:
                    selidx = VT_NUMCOUNTER;
                    break;
                default:
                    selidx = VT_VALUE;//追跡のデフォルトは値
                    break;
                
            }
            
        }
        switch(selidx){
            case VT_NUMCOUNTER:
                fixed = false;
                regpattern = "\\d";
                prepostpattern = "([^0-9]*)";
                break;
            case VT_NUMBERFIXED:
                fixed = true;
                regpattern = "\\d";
                prepostpattern = "([^0-9]*)";
                break;
            case VT_NUMBER:
                fixed = false;
                regpattern = "\\d";
                prepostpattern = "([^0-9]*)";
                break;
            case VT_ALPHANUMFIXED:
                fixed = true;
                if(ispath){
                    regpattern = "[0-9a-zA-Z]";
                }else{
                    if(isformdata){
                        regpattern = "[0-9a-zA-Z]";
                    }else{
                        regpattern = "[0-9a-zA-Z]";
                    }
                }
                prepostpattern = "([=;]*)";
                break;
            case VT_ALPHANUM:
                fixed = false;
                if(ispath){
                    regpattern = "[0-9a-zA-Z]";
                }else{
                    if(isformdata){
                        regpattern = "[0-9a-zA-Z]";
                    }else{
                        regpattern = "[0-9a-zA-Z]";
                    }
                }
                prepostpattern = "([=;]*)";
                break;
           case VT_PARAMVALUE:
                fixed = false;
                if(ispath){
                    regpattern = "[^=;/\\s]";
                }else{
                    if(isformdata){
                        regpattern = "[^=;\\s]";
                    }else{
                        regpattern = "[^=;&\\s]";
                    }
                }
                prepostpattern = "([=;]*)";
                break;
            case VT_VALUE:
            case VT_FIXED:
                wholeval = true;
                break;
        }
        String prefix = "";
        if(ispath){
            if(iswholepath){
                prefix = "";
            }else{
                prefix = "/[^/\\s]*?";
            }
        }else if(iscookie){
            prefix = "[^=]*?";
        }else if(isheader){
            prefix = "";
        }

        if (!wholeval){
            //Pattern pattern = ParmGenUtil.Pattern_compile("([^0-9]*)(\\d+)([^0-9]*)");
            Pattern pattern = ParmGenUtil.Pattern_compile(prepostpattern + "(" + regpattern+ "+)" + prepostpattern);
            Matcher matcher = pattern.matcher(v);
            if (matcher.find()){
                    String prestr = null;
                    String poststr = null;
                    String numstr = null;
                    int gcnt = matcher.groupCount();
                    String chrcnt = "";
                    for(int n = 0; n < gcnt ; n++){
                        switch(n){
                            case 0:
                                prestr = matcher.group(n+1);
                                break;
                            case 1:
                                numstr = matcher.group(n+1);
                                int l = numstr.length();
                                if ( l>0){
                                    if(fixed){
                                        chrcnt = "{" +Integer.toString(l) + "})";
                                    }else{
                                        chrcnt = "+)";
                                    }
                                }else{
                                    chrcnt = "+)";
                                }
                                break;
                            case 2:
                                poststr = matcher.group(n+1);
                                break;
                            default:
                                break;
                        }
                    }
                    if (isformdata){
                        return ParmGenUtil.escapeRegexChars(prestr) + "(" + regpattern + chrcnt + ParmGenUtil.escapeRegexChars(poststr) ;
                    }else{
                        return prefix + ParmGenUtil.escapeRegexChars(prestr) + "(" + regpattern + chrcnt+ ParmGenUtil.escapeRegexChars(poststr) ;
                    }
            }
        }
        if(iswholepath){
            return ParmGenUtil.getPathsRegex(v);
        }

        if(selidx==VT_FIXED ){//固定値を返す
            String escv = ParmGenUtil.escapeRegexChars(v);
            if(isformdata){
                return "(" + escv + ")";
            }
            return prefix + "(" + escv + ")";
        }
        
        if(isjson){
            return v;
        }
        
        if ( isformdata){
            return "(.+)";
        }
        if(isheader || ispath){
            return prefix + "([^\\r\\n\\t ]+)";
        }else if(iscookie){
            return prefix + "([^\\r\\n\\t;\\= ]+)";
        }
        return prefix + "([^&=\\r\\n\\t ]+)";
    }

    private void AddActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_AddActionPerformed
        // TODO add your handling code here:
        int[] rowsSelected = ReqParsedTable.getSelectedRows();
        String url = (String)Select_ReplaceTargetURL.getSelectedItem();
        String fromstr = ParmVars.session.get(ParmGenSession.K_FROMPOS);
        int frompos = -1;
        if(fromstr!=null){
            frompos = Integer.parseInt(fromstr);
        }
        String tostr = ParmVars.session.get(ParmGenSession.K_TOPOS);
        int topos = ParmVars.TOSTEPANY;
        if(tostr!=null){
            topos = Integer.parseInt(tostr);
        }
        parentwin.updateFromToPos(frompos, topos);
        
        if(topos>=0){//SetTo specified. then  URL target is any match
            url = ".*";
        }
        if(url!=null)  parentwin.updateTargetURL(url);
        

        for (int k=0; k<rowsSelected.length; k++){
            String reqplace = (String)ReqParsedTableModel.getValueAt(rowsSelected[k], 0);//位置
            String pname = (String)ReqParsedTableModel.getValueAt(rowsSelected[k], 1);//name
            String pvalue = (String)ReqParsedTableModel.getValueAt(rowsSelected[k], 2);//value
            boolean islastparam = false;
            if(k+1==rowsSelected.length){
                islastparam = true;
            }
            if (parentwin != null){
                // default regex pattern name=[^&]value(\d+)[^&]
                boolean ispath= false;
                boolean iscookie = false;
                boolean isheader = false;
                boolean iswholepath = false;
                boolean isjson = false;
                String cookiepref = "";
                String pathpref = "";
                String headerpref ="";
                if(reqplace.equals("path")){
                    String pathproto = selected_request.getPathPrefURL();

                    //if(!pathproto.isEmpty()){
                    //    pathpref = pathproto + "://[^/]+";
                    //}
                    int pn = Integer.parseInt(pname);
                    if(pn==0)iswholepath = true;
                    for(int j=1;j<pn;j++){
                        pathpref += "/[^/]*?";
                    }
                    ispath = true;
                    pname = null;
                }else if(reqplace.equals("header")){
                    headerpref = pname + ":[    ]*";
                    pname = null;
                    isheader = true;
                }else if(reqplace.equals("cookie")){
                    reqplace = "header";
                    cookiepref = "[Cc]ookie:.*?" + pname + "=";
                    pname = null;
                    iscookie = true;
                }else if(reqplace.equals("json")){
                    isjson = true;
                }

                
                parentwin.addParamToSelectedModel(reqplace, pname, k, headerpref + cookiepref + pathpref + getValueRegex(pvalue, ispath, iscookie, isheader,isjson, iswholepath), isformdata, islastparam);

            }
        }
        
        dispose();
    }//GEN-LAST:event_AddActionPerformed

    private void Select_ReplaceTargetURLActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Select_ReplaceTargetURLActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_Select_ReplaceTargetURLActionPerformed

    private void ValReplacePartActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ValReplacePartActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_ValReplacePartActionPerformed

   

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton Add;
    private javax.swing.JButton Cancel;
    private javax.swing.JTable ReqParsedTable;
    private javax.swing.JComboBox<String> Select_ReplaceTargetURL;
    private javax.swing.JComboBox<String> ValReplacePart;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane8;
    // End of variables declaration//GEN-END:variables

    @Override
    public void updateMessageAreaInSelectedModel(int panel) {
        //
    }
}
