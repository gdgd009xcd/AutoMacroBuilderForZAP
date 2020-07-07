/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.io.File;
import java.util.List;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;

import org.zaproxy.zap.extension.automacrobuilder.*;

/**
 *
 * @author tms783
 */
@SuppressWarnings("serial")
public class ParmGenNew extends javax.swing.JFrame implements InterfaceRegex, interfaceParmGenWin {
    
    private static org.apache.logging.log4j.Logger LOGGER4J = org.apache.logging.log4j.LogManager.getLogger();
    
    // 下記定数P_XXXは、ModelTabsの各タブの出現順序と一致しなければならない。
    // ModelTabsStateChangedでタブ切り替えた場合に、切り替えたタブの番号ModelTabs.getSelectedIndex()の返値と下記定数は
    // 対応している。
    public final static int P_NUMBERMODEL = 0;
    final static int P_CSVMODEL = 1;
    final static int P_TRACKMODEL = 2;
    final static int P_TAMPERMODEL = 3;
    final static int P_RANDOMMODEL = 4;//NOP


    //
    public final static int P_REQUESTTAB = 0;
    public final static int P_RESPONSETAB = 1;
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    private boolean current_model_selected = false;
    private boolean blockUnderInitComponents = true; // blocking behavior while running initComponents.
    
    private int current_model;

    int current_tablerowidx;
    int current_tablecolidx;

    int current_reqrespanel;



    AppParmsIni rec;
    AppParmsIni addrec;

    //起動元ウィンドウ
    private ParmGenTop parentwin;

    DefaultTableModel[] ParamTableModels={
        null, null, null, null,null
    };

    /**
     * Creates new form ParmGenNew
     */




    public ParmGenNew(ParmGenTop _parentwin, AppParmsIni _rec){

        current_tablerowidx = 0;

        parentwin = _parentwin;

        LOGGER4J.debug("initComponents started");
        blockUnderInitComponents = true;
        initComponents();
        blockUnderInitComponents = false; // blocking behavior while running initComponents.
        LOGGER4J.debug("initComponents end.");
        
        ParamTableModels[P_NUMBERMODEL] = (DefaultTableModel)nParamTable.getModel();
        ParamTableModels[P_CSVMODEL] = (DefaultTableModel)csvParamTable.getModel();
        ParamTableModels[P_TRACKMODEL] = (DefaultTableModel)trackTable.getModel();
        ParamTableModels[P_TAMPERMODEL] = (DefaultTableModel)tamperTable.getModel();

        addJComboBoxToJTable();


        PRequestResponse mess = ParmGenJSONSave.proxy_messages.get(0);
        String _url = mess.request.getURL();

        selected_requestURL.setText(_url);
        
        SwingUtilities.invokeLater(() -> {
            try {
                ParmGenTextDoc reqdoc = new ParmGenTextDoc(RequestArea);
                reqdoc.setRequestChunks(mess.request);
            } catch (Exception ex) {
                Logger.getLogger(ParmGenNew.class.getName()).log(Level.SEVERE, null, ex);
            }
           
        });
        
        current_model = P_NUMBERMODEL;

        if(_rec!=null){
            rec = _rec;
            //rec.setCntFileName();
            addrec = null;
            switch(rec.getTypeVal()){
                case AppParmsIni.T_NUMBER:
                    current_model = P_NUMBERMODEL;
                    break;
                case AppParmsIni.T_CSV:
                    current_model = P_CSVMODEL;
                    break;
                case AppParmsIni.T_TRACK:
                    current_model =  P_TRACKMODEL;
                    break;
                case AppParmsIni.T_RANDOM:
                    current_model = P_RANDOMMODEL;
                    break;
                case AppParmsIni.T_TAMPER:
                    current_model = P_TAMPERMODEL;
                    break;
            }
            
            current_model_selected = true;
            CSVrewind.setSelected(false);
            NumberRewind.setSelected(false);
        }else{
            rec = new AppParmsIni();//add new record
            //rec.setRow(parentwin.getRowSize());
            addrec = rec;
            CSVrewind.setSelected(true);
            NumberRewind.setSelected(true);
        }

        setAppParmsIni();


        ResponseArea.setToolTipText(bundle.getString("ParmGenNew.<HTML>※追跡パラメータの登録方法<BR>追跡する値を選択し、追加ボタンを押す。</HTML>.text"));
        
        if (current_model != P_TRACKMODEL) {
            TrackFromLabel.setEnabled(false);
            TrackFrom.setEnabled(false);
        }
        // after deternimed current_model_selected must run these functions.
        ModelTabs.setSelectedIndex(current_model);
        ModelTabs.setEnabledAt(3, false);

    }

    public void setPatternFileName(String _name){
        AttackPatternFile.setText(_name);
    }
    public int getCurrentModel(){
        return current_model;
    }

private void setAppParmsIni(){
        Object[] row;
        int tfrom = rec.getTrackFromStep();
        int tto = rec.getSetToStep();
        TrackFrom.setText(tfrom==-1?"*":Integer.toString(tfrom));
        SetTo.setText(tto==ParmVars.TOSTEPANY?"*":Integer.toString(tto));
        switch(current_model){
            case P_NUMBERMODEL:
                numberTargetURL.setText(rec.getUrl());
                NumberLen.setText(Integer.toString(rec.getLen()));
                NumberInit.setText(Integer.toString(rec.getIniVal()));
                rec.rewindAppValues();
                while((row=rec.getNextAppValuesRow())!=null){
                    ParamTableModels[P_NUMBERMODEL].addRow(row);
                }
                ResReqTabs.remove(ResPanel);
                break;
            case P_CSVMODEL:
                csvTargetURL.setText(rec.getUrl());
                csvFilePath.setText(rec.getFrlFileName());
                rec.rewindAppValues();
                CSVSkipLine.setText(rec.getCurrentValue());
                while((row=rec.getNextAppValuesRow())!=null){
                    ParamTableModels[P_CSVMODEL].addRow(row);
                }
                break;
            case P_TRACKMODEL:
                trackTargetURL.setText(rec.getUrl());
                rec.rewindAppValues();
                while((row=rec.getNextAppValuesRow())!=null){
                    ParamTableModels[P_TRACKMODEL].addRow(row);
                }
                break;
             case P_TAMPERMODEL:
                tamperTargetURL.setText(rec.getUrl());
                rec.rewindAppValues();
                while((row=rec.getNextAppValuesRow())!=null){
                    ParamTableModels[P_TAMPERMODEL].addRow(row);
                }
                break;
            default:
                break;
        }

        current_reqrespanel = P_REQUESTTAB;
    }

    private void clearTable(DefaultTableModel model){
        int rcnt = model.getRowCount();
        for(int i = 0 ; i < rcnt; i++){
            model.removeRow(0);
        }
    }
    private void addJComboBoxToJTable(){
        //ComboBoxを設定
        AppValue ap = new AppValue();//static 初期化。
        JComboBox<String> cb = new JComboBox<>(AppValue.makeTargetRequestParamTypes());
        JComboBox<String> tb = new JComboBox<>(AppValue.makePayloadPositionNames());
        DefaultCellEditor dce = new DefaultCellEditor(cb);
        DefaultCellEditor tbe = new DefaultCellEditor(tb);
        nParamTable. getColumnModel().getColumn(0).setCellEditor(dce);
        trackTable.getColumnModel().getColumn(0).setCellEditor(dce);
        tamperTable.getColumnModel().getColumn(0).setCellEditor(dce);
        tamperTable.getColumnModel().getColumn(6).setCellEditor(tbe);

        //modelの初期化とクリア
        for(int i = 0; i < ParamTableModels.length; i++){
            DefaultTableModel model = ParamTableModels[i];
            if ( model!=null){
                clearTable(model);
            }
        }
        numberTargetURL.setText("");
        NumberInit.setText("");
        NumberLen.setText("");
        NumberRewind.setSelected(false);



    }

    public String getRegex(){
        return getTableRowRegex();
    }

    public String getOriginal(){
        if (current_model == P_TRACKMODEL){
            if( current_tablecolidx > 2){
                return getResponseArea();
            }
        }
        return getRequestArea();
    }

    public void setRegex(String regex){
        updateTableRowRegex(regex);
    }

    public void addParamToSelectedModel(String reqplace, String name, int ni, String value, boolean target_req_isformdata, boolean islastparam){
        current_model_selected = true;
        addParam(current_model, reqplace, name, ni, value, target_req_isformdata, islastparam);
    }
    /*
     *  指定されたメッセージで、カレントのボタンのmessageAreaを更新
     */
    public void updateMessageAreaInSelectedModel(int panelno){
        PRequestResponse rs = ParmGenJSONSave.selected_messages.get(0);
        if(panelno==-1){
            panelno = current_reqrespanel;
        }
        String TargetURLRegex = ".*" + rs.request.getPath() + ".*";


        switch(panelno){
            case P_REQUESTTAB:
                ParmVars.session.put(ParmGenSession.K_REQUESTURLREGEX, TargetURLRegex);
                selected_requestURL.setText(rs.request.getURL());
                ParmVars.session.put(ParmGenSession.K_HEADERLENGTH, Integer.toString(rs.request.getHeaderLength()));
                // RequestArea.setText(rs.request.getMessage());
                ParmGenTextDoc reqdoc = new ParmGenTextDoc(RequestArea);
                reqdoc.setRequestChunks(rs.request);
                RequestArea.setCaretPosition(0);
                break;
            case P_RESPONSETAB:
                ParmVars.session.put(ParmGenSession.K_RESPONSEURLREGEX, TargetURLRegex);
                ParmVars.session.put(ParmGenSession.K_HEADERLENGTH, Integer.toString(rs.response.getHeaderLength()));
                selected_responseURL.setText(rs.request.getURL());
                // ResponseArea.setText(rs.response.getMessage());
                ParmGenTextDoc resdoc = new ParmGenTextDoc(ResponseArea);
                resdoc.setResponseChunks(rs.response);
                ResponseArea.setCaretPosition(0);
                break;
            default:
                break;

        }
    }

    private void addParam(int m, String reqplace, String name, int ni, String value, boolean target_req_isformdata, boolean islastparam){
        DefaultTableModel model = ParamTableModels[m];
        //name=valueにデフォルトの正規表現を生成してセット
        String nval =  (name!=null?("(?:[&=?]|^)" + name + "="):"") + value;
        String _reqplace = reqplace;
        if ( reqplace.toLowerCase().equals("formdata")){
            //nval = "(?:[A-Z].* name=\"" + ParmGenUtil.escapeRegexChars(name) + "\".*(?:\\r|\\n|\\r\\n))(?:[A-Z].*(?:\\r|\\n|\\r\\n)){0,}(?:\\r|\\n|\\r\\n)(?:.*?)" + value + "(?:.*?)(?:\\r|\\n|\\r\\n)";
            nval = "(?:[A-Z].* name=\"" + ParmGenUtil.escapeRegexChars(name) + "\".*(?:\\r|\\n|\\r\\n))(?:[A-Z].*(?:\\r|\\n|\\r\\n)){0,}(?:\\r|\\n|\\r\\n)(?:.*?)" + value ;

            _reqplace = "body";
        }else if(reqplace.toLowerCase().equals("json")){
            PRequestResponse selected_message = ParmGenJSONSave.selected_messages.get(0);
            PRequest request = selected_message.request;
            String regex = "\"" + name + "\"(?:[\\t \\r\\n]*):(?:[\\t\\[\\r\\n ]*)\"(.+?)\"(?:[\\t \\]\\r\\n]*)(?:,|})";
            List<String> jsonmatchlist = ParmGenUtil.getRegexMatchGroups(regex, request.getBody());
            boolean jsonmatched = false;
            String jsonvalue = value;
            /*for(String v: jsonmatchlist){
                if(jsonvalue.equals(v)){
                    jsonmatched = true;
                    break;
                }
            }*/
            if(jsonmatchlist!=null&&jsonmatchlist.size()>0){
                jsonmatched = true;
            }
            
            if(!jsonmatched){// "key": value
                regex ="\"" + name + "\"(?:[\\t \\r\\n]*):(?:[\\t\\[\\r\\n ]*)([^,:{}\\\"]+?)(?:[\\t \\]\\r\\n]*)(?:,|})";
                jsonmatchlist = ParmGenUtil.getRegexMatchGroups(regex, request.getBody());
                /*for(String v: jsonmatchlist){
                    if(jsonvalue.equals(v)){
                        jsonmatched = true;
                        break;
                    }
                }*/
                if(jsonmatchlist!=null&&jsonmatchlist.size()>0){
                    jsonmatched = true;
                }
            }
            nval = regex;
            _reqplace = "body";
        }
        Object []row = null;
        boolean urlencode = false;
        AppValue ap = new AppValue();

        String payloadposition = ParmVars.session.get(ParmGenSession.K_PAYLOADPOSITION);
        if(payloadposition==null){
            payloadposition = ap.getPayloadPositionName(AppValue.I_APPEND);
        }
        String tkname = "";
        String responseURLregex = ParmVars.session.get(ParmGenSession.K_RESPONSEURLREGEX);
        String frompos = TrackFrom.getText();
        int fromnum = -1;
        if(frompos!=null&&!frompos.isEmpty()){
            try{
                fromnum = Integer.parseInt(frompos);
            }catch(NumberFormatException e){
                fromnum = -1;
            }
            
            if(fromnum>-1){//TrackFrom is specified. then Tracking From target URL is any match 
                responseURLregex = ".*";
            }
        }
        switch(m){
            case P_NUMBERMODEL:
                row = new Object[]{_reqplace, false, nval, islastparam};
                break;
            case P_CSVMODEL:
                row = new Object[]{_reqplace, false, Integer.parseInt(ParmVars.session.get(ni, ParmGenSession.K_COLUMN)), nval, islastparam};
                break;
            case P_TAMPERMODEL://とりあえず、パラメータレコードを作成し、この時点では一部のデータをセットする。
                //置換位置　   置換する・しない　Value　Name　Attack(未使用)　Advance　Position　URLencode
                // _reqplace  false            nval   name  ""      "0"       "append"        false
                row = new Object[]{_reqplace, false, nval, name, "", "0" , payloadposition , false};
                break;
            case P_TRACKMODEL:
                if(ParmVars.session.get(0, ParmGenSession.K_TOKEN)==null){
                    urlencode = false;
                    if(target_req_isformdata!=true){
                        if(Boolean.parseBoolean(ParmVars.session.get(ParmGenSession.K_URLENCODE))==true){
                            //引き継ぎ先リクエストがformdataではなく、引き継ぎ元リクエストがレスポンスボディ。
                            urlencode = true;
                        }
                    }
                    tkname = ParmVars.session.get(ParmGenSession.K_TOKEN);
                    if(tkname==null||tkname.isEmpty()){
                        tkname = name;
                    }
                    row = new Object[]{_reqplace, false, nval,
                    responseURLregex,
                    ParmVars.session.get(ParmGenSession.K_RESPONSEREGEX),
                    ParmVars.session.get(ParmGenSession.K_RESPONSEPART),
                    ParmVars.session.get(ParmGenSession.K_RESPONSEPOSITION),
                    tkname,
                    urlencode,"*","*",ParmVars.session.get(ParmGenSession.K_TOKENTYPE)
                    };
                }else{
                    String _token;
                    if((_token=ParmVars.session.get(ni, ParmGenSession.K_TOKEN))!=null){
                        urlencode = false;
                        if(target_req_isformdata!=true){
                            if(Boolean.parseBoolean(ParmVars.session.get(ni, ParmGenSession.K_URLENCODE))==true){
                                urlencode = true;
                            }
                        }
                        tkname = ParmVars.session.get(ni, ParmGenSession.K_TOKEN);
                        if(tkname==null||tkname.isEmpty()){
                            tkname = name;
                        }
                        row = new Object[]{_reqplace, false, nval,
                        responseURLregex,
                        ParmVars.session.get(ni, ParmGenSession.K_RESPONSEREGEX),
                        ParmVars.session.get(ni, ParmGenSession.K_RESPONSEPART),
                        ParmVars.session.get(ni, ParmGenSession.K_RESPONSEPOSITION),
                        tkname,
                        urlencode,"*","*",ParmVars.session.get(ni, ParmGenSession.K_TOKENTYPE)
                        };
                    }
                }
                break;

        }

        if(row !=null){
            model.addRow(row);
        }
    }
    public void updateFromToPos(int frompos, int topos){
        String trfromstr = Integer.toString(frompos);
        if(frompos<0){
            trfromstr = "*";
        }
        TrackFrom.setText(trfromstr);
        String settostr = Integer.toString(topos);
        if(topos<0||topos==ParmVars.TOSTEPANY){
           settostr = "*";
        }
        SetTo.setText(settostr);
    }
    
    /*
     * current_modelのtargetURLを更新
     */
    public void updateTargetURL(String targetURL){
        String mname = "";
        switch(current_model){
            case P_NUMBERMODEL:
                mname = "NUMBERMODEL";
                numberTargetURL.setText(targetURL);
                break;
            case P_CSVMODEL:
                mname = "CSVMODEL";
                csvTargetURL.setText(targetURL);
                break;
            case P_TRACKMODEL:
                mname = "TRACKMODEL";
                trackTargetURL.setText(targetURL);
                break;
            case P_RANDOMMODEL:
                mname = "RANDOMMODEL";
                break;
            case P_TAMPERMODEL:
                mname = "TAMPERMODEL";
                tamperTargetURL.setText(targetURL);
                new ParmGenAttackListDialog(this, true, "").setVisible(true);
                break;
            default:
                mname = "UNKNOWNMODEL";
                break;
        }
        //ParmVars.plog.debuglog(0, mname);
    }

    /*
     * current_modelのtargetURLを返す
     */
    public String getTargetURL(){
        switch(current_model){
            case P_NUMBERMODEL:
                return numberTargetURL.getText();
            case P_CSVMODEL:
                return csvTargetURL.getText();
            case P_TRACKMODEL:
                return trackTargetURL.getText();
            case P_RANDOMMODEL:
                break;
            case P_TAMPERMODEL:
                return tamperTargetURL.getText();
            default:
                break;
        }
        return "";
    }

    @SuppressWarnings("fallthrough")
    private JTable getCurrentTable(){
        JTable current_table = null;

        switch(current_model){
            case P_NUMBERMODEL:
                current_table = nParamTable;
            case P_CSVMODEL:
                current_table = csvParamTable;
            case P_TRACKMODEL:
                current_table = trackTable;
            case P_RANDOMMODEL:
                break;
            case P_TAMPERMODEL:
                current_table = tamperTable;
                break;
            default:
                break;
        }
        return current_table;
    }

    public void updateTableRowRegex(String regex){
        int pos = current_tablecolidx;
        if(current_model==P_CSVMODEL){
            pos = 3;
        }
        ParamTableModels[current_model].setValueAt(regex, current_tablerowidx, pos);

    }

    public String getTableRowRegex(){
        int pos = current_tablecolidx;
        if(current_model==P_CSVMODEL){
            pos = 3;
        }
        return (String)ParamTableModels[current_model].getValueAt(current_tablerowidx, pos);
    }

    public String getRequestArea(){
        return RequestArea.getText();
    }

    public String getResponseArea(){
        return ResponseArea.getText();
    }

    public ParmGenJSONSave getCSV(){
        return parentwin.csv;
    }
    
    private void selectNumberCounterTypeCompo(AppParmsIni.NumberCounterTypes _ntype){
        boolean NumberCountEnabled = false;
        boolean DateCountEnabled = false;
        switch(_ntype){
            
            case DateCount:
                DateCountEnabled = true;
                break;
            case NumberCount:
            default:
                NumberCountEnabled = true;
                break;
        }
        NumberInit.setEnabled(NumberCountEnabled);
        NumberLen.setEnabled(NumberCountEnabled);
        NumberRewind.setEnabled(NumberCountEnabled);
        SimpleDateFormatStr.setEnabled(DateCountEnabled);
        AddMsec.setEnabled(DateCountEnabled);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings({"unchecked","rawtypes","serial"})
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup1 = new javax.swing.ButtonGroup();
        ModelTabs = new javax.swing.JTabbedPane();
        SeqNumber = new javax.swing.JPanel();
        NumberRegexTest = new javax.swing.JButton();
        nParamDel = new javax.swing.JButton();
        nParamUP = new javax.swing.JButton();
        nParamDOWN = new javax.swing.JButton();
        jScrollPane3 = new javax.swing.JScrollPane();
        nParamTable = new javax.swing.JTable();
        nParamAdd = new javax.swing.JButton();
        numberTargetURL = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        jPanel2 = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        NumberInit = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        NumberLen = new javax.swing.JTextField();
        NumberRewind = new javax.swing.JCheckBox();
        NumberSelBtn = new javax.swing.JRadioButton();
        DateSelBtn = new javax.swing.JRadioButton();
        SimpleDateFlabel = new javax.swing.JLabel();
        SimpleDateFormatStr = new javax.swing.JTextField();
        MsecLabel = new javax.swing.JLabel();
        AddMsec = new javax.swing.JTextField();
        SeqCSV = new javax.swing.JPanel();
        jButton6 = new javax.swing.JButton();
        csvFilePath = new javax.swing.JTextField();
        csvParamAdd = new javax.swing.JButton();
        csvParamDel = new javax.swing.JButton();
        csvParamUP = new javax.swing.JButton();
        csvParamDOWN = new javax.swing.JButton();
        csvParamRegexTest = new javax.swing.JButton();
        csvTargetURL = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        jScrollPane4 = new javax.swing.JScrollPane();
        csvParamTable = new javax.swing.JTable();
        jPanel1 = new javax.swing.JPanel();
        CSVrewind = new javax.swing.JCheckBox();
        CSVSkipLine = new javax.swing.JTextField();
        SeqResponse = new javax.swing.JPanel();
        nParamAdd4 = new javax.swing.JButton();
        nParamDel12 = new javax.swing.JButton();
        nParamDel13 = new javax.swing.JButton();
        nParamDel14 = new javax.swing.JButton();
        jButton10 = new javax.swing.JButton();
        jScrollPane6 = new javax.swing.JScrollPane();
        trackTable = new javax.swing.JTable();
        jLabel9 = new javax.swing.JLabel();
        trackTargetURL = new javax.swing.JTextField();
        SeqRandom = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        tamperTargetURL = new javax.swing.JTextField();
        jScrollPane5 = new javax.swing.JScrollPane();
        tamperTable = new javax.swing.JTable();
        addTamper = new javax.swing.JButton();
        upTamper = new javax.swing.JButton();
        delTamper = new javax.swing.JButton();
        downTamper = new javax.swing.JButton();
        modTamper = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        AttackPatternFile = new javax.swing.JTextField();
        jSeparator1 = new javax.swing.JSeparator();
        SaveParm = new javax.swing.JButton();
        CancelParm = new javax.swing.JButton();
        RequestSelectBtn = new javax.swing.JButton();
        ResReqTabs = new javax.swing.JTabbedPane();
        ReqPanel = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        RequestArea = new javax.swing.JTextPane();
        selected_requestURL = new javax.swing.JTextField();
        ResPanel = new javax.swing.JPanel();
        jScrollPane2 = new javax.swing.JScrollPane();
        ResponseArea = new javax.swing.JTextPane();
        selected_responseURL = new javax.swing.JTextField();
        TrackFromLabel = new javax.swing.JLabel();
        TrackFrom = new javax.swing.JTextField();
        SetToLabel = new javax.swing.JLabel();
        SetTo = new javax.swing.JTextField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle(bundle.getString("ParmGenNew.PARMGEN編集画面.text")); // NOI18N

        ModelTabs.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                ModelTabsStateChanged(evt);
            }
        });

        NumberRegexTest.setText(bundle.getString("ParmGenNew.正規表現テスト.text")); // NOI18N
        NumberRegexTest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                NumberRegexTestActionPerformed(evt);
            }
        });

        nParamDel.setText(bundle.getString("ParmGenNew.削除.text")); // NOI18N
        nParamDel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nParamDelActionPerformed(evt);
            }
        });

        nParamUP.setText(bundle.getString("ParmGenNew.▲UP  .text")); // NOI18N
        nParamUP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nParamUPActionPerformed(evt);
            }
        });

        nParamDOWN.setText(bundle.getString("ParmGenNew.▼DOWN.text")); // NOI18N
        nParamDOWN.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nParamDOWNActionPerformed(evt);
            }
        });

        nParamTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "", "", "", ""
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Object.class, java.lang.Boolean.class, java.lang.String.class, java.lang.Boolean.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        nParamTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        nParamTable.getTableHeader().setReorderingAllowed(false);
        jScrollPane3.setViewportView(nParamTable);
        if (nParamTable.getColumnModel().getColumnCount() > 0) {
            nParamTable.getColumnModel().getColumn(0).setPreferredWidth(60);
            nParamTable.getColumnModel().getColumn(0).setHeaderValue(bundle.getString("ParmGenNew.nParamTable.title0.text")); // NOI18N
            nParamTable.getColumnModel().getColumn(1).setPreferredWidth(60);
            nParamTable.getColumnModel().getColumn(1).setHeaderValue(bundle.getString("ParmGenNew.nParamTable.title1.text")); // NOI18N
            nParamTable.getColumnModel().getColumn(2).setPreferredWidth(150);
            nParamTable.getColumnModel().getColumn(2).setHeaderValue(bundle.getString("ParmGenNew.nParamTable.title2.text")); // NOI18N
            nParamTable.getColumnModel().getColumn(3).setHeaderValue(bundle.getString("ParmGenNew.nParamTable.title3.text")); // NOI18N
        }

        nParamAdd.setText(bundle.getString("ParmGenNew.追加.text")); // NOI18N
        nParamAdd.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nParamAddActionPerformed(evt);
            }
        });

        numberTargetURL.setText(".*/input.php.*");
        numberTargetURL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                numberTargetURLActionPerformed(evt);
            }
        });

        jLabel5.setText(bundle.getString("ParmGenNew.置換対象パス.text")); // NOI18N

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder(bundle.getString("ParmGenNew.jPanel2.border.title.text"))); // NOI18N

        jLabel2.setText(bundle.getString("ParmGenNew.初期値.text")); // NOI18N

        NumberInit.setText("1");
        NumberInit.setToolTipText(bundle.getString("ParmGenNew.最大2147483647まで.text")); // NOI18N
        NumberInit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                NumberInitActionPerformed(evt);
            }
        });

        jLabel3.setText(bundle.getString("ParmGenNew.桁数.text")); // NOI18N

        NumberLen.setText("4");
        NumberLen.setToolTipText(bundle.getString("ParmGenNew.最大10ケタまで.text")); // NOI18N
        NumberLen.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                NumberLenActionPerformed(evt);
            }
        });

        NumberRewind.setSelected(true);
        NumberRewind.setText(bundle.getString("ParmGenNew.カウンタを初期化する.text")); // NOI18N
        NumberRewind.setToolTipText(bundle.getString("ParmGenNew.<HTML>カウンタを初期値で初期化する場合は、チェック.text")); // NOI18N
        NumberRewind.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                NumberRewindActionPerformed(evt);
            }
        });

        buttonGroup1.add(NumberSelBtn);
        NumberSelBtn.setSelected(true);
        NumberSelBtn.setText(bundle.getString("ParmGenNew.NumberTitle.text")); // NOI18N
        NumberSelBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                NumberSelBtnActionPerformed(evt);
            }
        });

        buttonGroup1.add(DateSelBtn);
        java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("burp/Bundle"); // NOI18N
        DateSelBtn.setText(bundle.getString("ParmGenNew.DateTimeTitle.text")); // NOI18N
        DateSelBtn.setEnabled(false);
        DateSelBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                DateSelBtnActionPerformed(evt);
            }
        });

        SimpleDateFlabel.setText("format");
        SimpleDateFlabel.setEnabled(false);

        SimpleDateFormatStr.setText("jTextField1");
        SimpleDateFormatStr.setEnabled(false);

        MsecLabel.setText("+msec");

        AddMsec.setText("0");
        AddMsec.setEnabled(false);

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(NumberSelBtn)
                    .addComponent(DateSelBtn))
                .addGap(55, 55, 55)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(SimpleDateFlabel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(18, 18, 18)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(NumberInit, javax.swing.GroupLayout.PREFERRED_SIZE, 46, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jLabel3)
                        .addGap(19, 19, 19)
                        .addComponent(NumberLen, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(NumberRewind)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addComponent(SimpleDateFormatStr, javax.swing.GroupLayout.PREFERRED_SIZE, 360, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(MsecLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 50, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(AddMsec, javax.swing.GroupLayout.PREFERRED_SIZE, 151, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 0, Short.MAX_VALUE))))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(NumberInit, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel3)
                    .addComponent(NumberLen, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(NumberRewind)
                    .addComponent(NumberSelBtn))
                .addGap(18, 18, 18)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(DateSelBtn)
                    .addComponent(SimpleDateFlabel)
                    .addComponent(SimpleDateFormatStr, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(MsecLabel)
                    .addComponent(AddMsec, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(20, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout SeqNumberLayout = new javax.swing.GroupLayout(SeqNumber);
        SeqNumber.setLayout(SeqNumberLayout);
        SeqNumberLayout.setHorizontalGroup(
            SeqNumberLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(SeqNumberLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(SeqNumberLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(SeqNumberLayout.createSequentialGroup()
                        .addComponent(jLabel5)
                        .addGap(19, 19, 19)
                        .addComponent(numberTargetURL, javax.swing.GroupLayout.PREFERRED_SIZE, 338, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(57, 532, Short.MAX_VALUE))
                    .addGroup(SeqNumberLayout.createSequentialGroup()
                        .addGroup(SeqNumberLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(SeqNumberLayout.createSequentialGroup()
                                .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, 791, Short.MAX_VALUE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(SeqNumberLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(NumberRegexTest, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(nParamUP, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(nParamDOWN, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(nParamDel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(nParamAdd, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(12, 12, 12)))
                        .addContainerGap())))
        );
        SeqNumberLayout.setVerticalGroup(
            SeqNumberLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(SeqNumberLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(SeqNumberLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(numberTargetURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel5))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(13, 13, 13)
                .addGroup(SeqNumberLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 141, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(SeqNumberLayout.createSequentialGroup()
                        .addComponent(nParamAdd, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(nParamDel, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(nParamUP, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(nParamDOWN, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(NumberRegexTest, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(47, Short.MAX_VALUE))
        );

        ModelTabs.addTab(bundle.getString("ParmGenNew.SeqNumber.TabConstrains.tabTitle.text"), SeqNumber); // NOI18N

        jButton6.setText(bundle.getString("ParmGenNew.CSVファイル選択.text")); // NOI18N
        jButton6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton6ActionPerformed(evt);
            }
        });

        csvFilePath.setText("C:\\windows\\sample.csv");
        csvFilePath.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                csvFilePathActionPerformed(evt);
            }
        });

        csvParamAdd.setText(bundle.getString("ParmGenNew.追加.text")); // NOI18N
        csvParamAdd.setMaximumSize(new java.awt.Dimension(107, 23));
        csvParamAdd.setMinimumSize(new java.awt.Dimension(107, 23));
        csvParamAdd.setPreferredSize(new java.awt.Dimension(107, 23));
        csvParamAdd.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                csvParamAddActionPerformed(evt);
            }
        });

        csvParamDel.setText(bundle.getString("ParmGenNew.削除.text")); // NOI18N
        csvParamDel.setMaximumSize(new java.awt.Dimension(107, 23));
        csvParamDel.setMinimumSize(new java.awt.Dimension(107, 23));
        csvParamDel.setPreferredSize(new java.awt.Dimension(107, 23));
        csvParamDel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                csvParamDelActionPerformed(evt);
            }
        });

        csvParamUP.setText(bundle.getString("ParmGenNew.▲UP  .text")); // NOI18N
        csvParamUP.setMaximumSize(new java.awt.Dimension(107, 23));
        csvParamUP.setMinimumSize(new java.awt.Dimension(107, 23));
        csvParamUP.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                csvParamUPActionPerformed(evt);
            }
        });

        csvParamDOWN.setText(bundle.getString("ParmGenNew.▼DOWN.text")); // NOI18N
        csvParamDOWN.setMaximumSize(new java.awt.Dimension(107, 23));
        csvParamDOWN.setMinimumSize(new java.awt.Dimension(107, 23));
        csvParamDOWN.setPreferredSize(new java.awt.Dimension(107, 23));
        csvParamDOWN.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                csvParamDOWNActionPerformed(evt);
            }
        });

        csvParamRegexTest.setText(bundle.getString("ParmGenNew.正規表現テスト.text")); // NOI18N
        csvParamRegexTest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                csvParamRegexTestActionPerformed(evt);
            }
        });

        csvTargetURL.setText(".*/input.php.*");
        csvTargetURL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                csvTargetURLActionPerformed(evt);
            }
        });

        jLabel6.setText(bundle.getString("ParmGenNew.置換対象パス.text")); // NOI18N

        csvParamTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null, null},
                {null, null, null, null, null},
                {null, null, null, null, null},
                {null, null, null, null, null}
            },
            new String [] {
                "置換位置", "置換しない", "ＣＳＶカラム", "置換パターン", "インクリメント"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Object.class, java.lang.Boolean.class, java.lang.Integer.class, java.lang.Object.class, java.lang.Boolean.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        csvParamTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        csvParamTable.getTableHeader().setReorderingAllowed(false);
        jScrollPane4.setViewportView(csvParamTable);
        if (csvParamTable.getColumnModel().getColumnCount() > 0) {
            csvParamTable.getColumnModel().getColumn(0).setPreferredWidth(60);
            csvParamTable.getColumnModel().getColumn(0).setHeaderValue(bundle.getString("ParmGenNew.csvParamTable.title0.text")); // NOI18N
            csvParamTable.getColumnModel().getColumn(1).setPreferredWidth(60);
            csvParamTable.getColumnModel().getColumn(1).setHeaderValue(bundle.getString("ParmGenNew.csvParamTable.title1.text")); // NOI18N
            csvParamTable.getColumnModel().getColumn(2).setHeaderValue(bundle.getString("ParmGenNew.csvParamTable.title2.text")); // NOI18N
            csvParamTable.getColumnModel().getColumn(3).setPreferredWidth(150);
            csvParamTable.getColumnModel().getColumn(3).setHeaderValue(bundle.getString("ParmGenNew.csvParamTable.title3.text")); // NOI18N
            csvParamTable.getColumnModel().getColumn(4).setHeaderValue(bundle.getString("ParmGenNew.csvParamTable.title4.text")); // NOI18N
        }

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder(bundle.getString("ParmGenNew.jPanel1.title.text"))); // NOI18N

        CSVrewind.setSelected(true);
        CSVrewind.setText(bundle.getString("ParmGenNew.カウンタを初期化する.text")); // NOI18N
        CSVrewind.setToolTipText(bundle.getString("ParmGenNew.<HTML>カウンタを初期値で初期化する際は、チェック.text")); // NOI18N
        CSVrewind.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CSVrewindActionPerformed(evt);
            }
        });

        CSVSkipLine.setText("0");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addComponent(CSVSkipLine, javax.swing.GroupLayout.PREFERRED_SIZE, 81, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(CSVrewind)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(CSVSkipLine, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(CSVrewind))
        );

        javax.swing.GroupLayout SeqCSVLayout = new javax.swing.GroupLayout(SeqCSV);
        SeqCSV.setLayout(SeqCSVLayout);
        SeqCSVLayout.setHorizontalGroup(
            SeqCSVLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(SeqCSVLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(SeqCSVLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jPanel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(SeqCSVLayout.createSequentialGroup()
                        .addComponent(jButton6, javax.swing.GroupLayout.PREFERRED_SIZE, 126, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(csvFilePath))
                    .addGroup(SeqCSVLayout.createSequentialGroup()
                        .addComponent(jLabel6)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 38, Short.MAX_VALUE)
                        .addComponent(csvTargetURL, javax.swing.GroupLayout.PREFERRED_SIZE, 670, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.Alignment.LEADING))
                .addGroup(SeqCSVLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(SeqCSVLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(SeqCSVLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(SeqCSVLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addGroup(SeqCSVLayout.createSequentialGroup()
                                    .addGap(24, 24, 24)
                                    .addComponent(csvParamDel, javax.swing.GroupLayout.DEFAULT_SIZE, 146, Short.MAX_VALUE))
                                .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, SeqCSVLayout.createSequentialGroup()
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(csvParamAdd, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, SeqCSVLayout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(csvParamUP, javax.swing.GroupLayout.DEFAULT_SIZE, 146, Short.MAX_VALUE)))
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, SeqCSVLayout.createSequentialGroup()
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(csvParamDOWN, javax.swing.GroupLayout.DEFAULT_SIZE, 146, Short.MAX_VALUE)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, SeqCSVLayout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(csvParamRegexTest, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );

        SeqCSVLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {csvParamDOWN, csvParamDel, csvParamRegexTest, csvParamUP});

        SeqCSVLayout.setVerticalGroup(
            SeqCSVLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(SeqCSVLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(SeqCSVLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton6)
                    .addComponent(csvFilePath, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addGroup(SeqCSVLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(csvTargetURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel6)
                    .addComponent(csvParamAdd, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGroup(SeqCSVLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(SeqCSVLayout.createSequentialGroup()
                        .addGap(3, 3, 3)
                        .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, 89, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(SeqCSVLayout.createSequentialGroup()
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(csvParamDel, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(csvParamUP, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(csvParamDOWN, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(csvParamRegexTest, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(135, Short.MAX_VALUE))
        );

        ModelTabs.addTab(bundle.getString("ParmGenNew.SeqCSV.TabConstraints.tabTitle.text"), SeqCSV); // NOI18N

        nParamAdd4.setText(bundle.getString("ParmGenNew.追加.text")); // NOI18N
        nParamAdd4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nParamAdd4ActionPerformed(evt);
            }
        });

        nParamDel12.setText(bundle.getString("ParmGenNew.削除.text")); // NOI18N
        nParamDel12.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nParamDel12ActionPerformed(evt);
            }
        });

        nParamDel13.setText(bundle.getString("ParmGenNew.▲UP  .text")); // NOI18N
        nParamDel13.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nParamDel13ActionPerformed(evt);
            }
        });

        nParamDel14.setText(bundle.getString("ParmGenNew.▼DOWN.text")); // NOI18N
        nParamDel14.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nParamDel14ActionPerformed(evt);
            }
        });

        jButton10.setText(bundle.getString("ParmGenNew.正規表現テスト.text")); // NOI18N
        jButton10.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton10ActionPerformed(evt);
            }
        });

        trackTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null, null, null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null, null, null, null, null, null}
            },
            new String [] {
                "置換箇所", "置換しない", "置換正規表現", "追跡URL", "追跡正規表現", "追跡箇所", "追跡位置", "追跡NAME値", "URLencodeする", "", "", "tokentype"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Object.class, java.lang.Boolean.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.String.class, java.lang.Boolean.class, java.lang.String.class, java.lang.String.class, java.lang.String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        trackTable.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_OFF);
        trackTable.getTableHeader().setReorderingAllowed(false);
        jScrollPane6.setViewportView(trackTable);
        if (trackTable.getColumnModel().getColumnCount() > 0) {
            trackTable.getColumnModel().getColumn(0).setPreferredWidth(60);
            trackTable.getColumnModel().getColumn(0).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title0.text")); // NOI18N
            trackTable.getColumnModel().getColumn(1).setPreferredWidth(60);
            trackTable.getColumnModel().getColumn(1).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title1.text")); // NOI18N
            trackTable.getColumnModel().getColumn(2).setPreferredWidth(150);
            trackTable.getColumnModel().getColumn(2).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title2.text")); // NOI18N
            trackTable.getColumnModel().getColumn(3).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title3.text")); // NOI18N
            trackTable.getColumnModel().getColumn(4).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title4.text")); // NOI18N
            trackTable.getColumnModel().getColumn(5).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title5.text")); // NOI18N
            trackTable.getColumnModel().getColumn(6).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title6.text")); // NOI18N
            trackTable.getColumnModel().getColumn(7).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title7.text")); // NOI18N
            trackTable.getColumnModel().getColumn(8).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title8.text")); // NOI18N
            trackTable.getColumnModel().getColumn(9).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title9.text")); // NOI18N
            trackTable.getColumnModel().getColumn(10).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title10.text")); // NOI18N
            trackTable.getColumnModel().getColumn(11).setHeaderValue(bundle.getString("ParmGenNew.trackTable.title11.text")); // NOI18N
        }

        jLabel9.setText(bundle.getString("ParmGenNew.置換対象パス.text")); // NOI18N

        trackTargetURL.setText(".*/input.php.*");
        trackTargetURL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                trackTargetURLActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout SeqResponseLayout = new javax.swing.GroupLayout(SeqResponse);
        SeqResponse.setLayout(SeqResponseLayout);
        SeqResponseLayout.setHorizontalGroup(
            SeqResponseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(SeqResponseLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(SeqResponseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane6, javax.swing.GroupLayout.DEFAULT_SIZE, 811, Short.MAX_VALUE)
                    .addGroup(SeqResponseLayout.createSequentialGroup()
                        .addComponent(jLabel9)
                        .addGap(36, 36, 36)
                        .addComponent(trackTargetURL)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(SeqResponseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButton10, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(nParamDel14, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(nParamDel13, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(nParamDel12, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(nParamAdd4, javax.swing.GroupLayout.PREFERRED_SIZE, 133, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(17, 17, 17))
        );
        SeqResponseLayout.setVerticalGroup(
            SeqResponseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(SeqResponseLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(SeqResponseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(trackTargetURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel9))
                .addGap(36, 36, 36)
                .addGroup(SeqResponseLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane6, javax.swing.GroupLayout.PREFERRED_SIZE, 223, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(SeqResponseLayout.createSequentialGroup()
                        .addComponent(nParamAdd4)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(nParamDel12)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(nParamDel13)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(nParamDel14)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton10)))
                .addContainerGap())
        );

        ModelTabs.addTab(bundle.getString("ParmGenNew.SeqResponse.TabConstraints.tabTitle.text"), SeqResponse); // NOI18N

        jLabel1.setText(bundle.getString("ParmGenNew.対象パス.text")); // NOI18N

        tamperTargetURL.setText("jTextField1");

        tamperTable.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {"post", null, null, "param1", "SQL injection", null, "add", null},
                {"", null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null, null},
                {null, null, null, null, null, null, null, null}
            },
            new String [] {
                "置換位置", "置換しない", "Value", "Name", "Attack", "Advance", "Position", "ＵＲＬencode"
            }
        ) {
            Class[] types = new Class [] {
                java.lang.Object.class, java.lang.Boolean.class, java.lang.Object.class, java.lang.Object.class, java.lang.Object.class, java.lang.Integer.class, java.lang.Object.class, java.lang.Boolean.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        tamperTable.getTableHeader().setReorderingAllowed(false);
        jScrollPane5.setViewportView(tamperTable);

        addTamper.setText(bundle.getString("ParmGenNew.追加.text")); // NOI18N
        addTamper.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addTamperActionPerformed(evt);
            }
        });

        upTamper.setText(bundle.getString("ParmGenNew.▲.text")); // NOI18N
        upTamper.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                upTamperActionPerformed(evt);
            }
        });

        delTamper.setText(bundle.getString("ParmGenNew.削除.text")); // NOI18N
        delTamper.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                delTamperActionPerformed(evt);
            }
        });

        downTamper.setText(bundle.getString("ParmGenNew.▼.text")); // NOI18N
        downTamper.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                downTamperActionPerformed(evt);
            }
        });

        modTamper.setText(bundle.getString("ParmGenNew.編集.text")); // NOI18N
        modTamper.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                modTamperActionPerformed(evt);
            }
        });

        jLabel4.setText(bundle.getString("ParmGenNew.パターン.text")); // NOI18N

        AttackPatternFile.setText("jTextField1");

        javax.swing.GroupLayout SeqRandomLayout = new javax.swing.GroupLayout(SeqRandom);
        SeqRandom.setLayout(SeqRandomLayout);
        SeqRandomLayout.setHorizontalGroup(
            SeqRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(SeqRandomLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(SeqRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(SeqRandomLayout.createSequentialGroup()
                        .addGroup(SeqRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane5)
                            .addGroup(SeqRandomLayout.createSequentialGroup()
                                .addComponent(jLabel1)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(tamperTargetURL)))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(SeqRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(SeqRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(addTamper, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(upTamper, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(delTamper, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(downTamper, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(modTamper, javax.swing.GroupLayout.PREFERRED_SIZE, 99, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(58, 58, 58))
                    .addGroup(SeqRandomLayout.createSequentialGroup()
                        .addComponent(jLabel4)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(AttackPatternFile)
                        .addGap(164, 164, 164))))
        );
        SeqRandomLayout.setVerticalGroup(
            SeqRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(SeqRandomLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(SeqRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(tamperTargetURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(SeqRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(AttackPatternFile, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(SeqRandomLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(SeqRandomLayout.createSequentialGroup()
                        .addComponent(addTamper)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(modTamper)
                        .addGap(15, 15, 15)
                        .addComponent(delTamper)
                        .addGap(11, 11, 11)
                        .addComponent(upTamper)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(downTamper))
                    .addComponent(jScrollPane5, javax.swing.GroupLayout.PREFERRED_SIZE, 190, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(99, 99, 99))
        );

        ModelTabs.addTab("Tamper", SeqRandom);

        SaveParm.setText(bundle.getString("ParmGenNew.保存.text")); // NOI18N
        SaveParm.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SaveParmActionPerformed(evt);
            }
        });

        CancelParm.setText(bundle.getString("ParmGenNew.取消.text")); // NOI18N
        CancelParm.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CancelParmActionPerformed(evt);
            }
        });

        RequestSelectBtn.setText(bundle.getString("ParmGenNew.リクエスト/レスポンス選択する.text")); // NOI18N
        RequestSelectBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RequestSelectBtnActionPerformed(evt);
            }
        });

        ResReqTabs.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                ResReqTabsStateChanged(evt);
            }
        });

        RequestArea.setEditorKit(new TextPaneLineWrapper());
        RequestArea.setAutoscrolls(false);
        RequestArea.setPreferredSize(new java.awt.Dimension(1000, 1500));
        jScrollPane1.setViewportView(RequestArea);

        selected_requestURL.setText("http:///xxxx");
        selected_requestURL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                selected_requestURLActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout ReqPanelLayout = new javax.swing.GroupLayout(ReqPanel);
        ReqPanel.setLayout(ReqPanelLayout);
        ReqPanelLayout.setHorizontalGroup(
            ReqPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ReqPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(ReqPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(selected_requestURL, javax.swing.GroupLayout.DEFAULT_SIZE, 955, Short.MAX_VALUE)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 955, Short.MAX_VALUE))
                .addContainerGap())
        );
        ReqPanelLayout.setVerticalGroup(
            ReqPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ReqPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(selected_requestURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 39, Short.MAX_VALUE)
                .addGap(28, 28, 28))
        );

        ResReqTabs.addTab(bundle.getString("ParmGenNew.ReqPanel.TabConstraints.tabTitle.text"), ReqPanel); // NOI18N

        jScrollPane2.setHorizontalScrollBarPolicy(javax.swing.ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        ResponseArea.setEditorKit(new TextPaneLineWrapper());
        jScrollPane2.setViewportView(ResponseArea);

        selected_responseURL.setText("http://aaaa");
        selected_responseURL.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                selected_responseURLActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout ResPanelLayout = new javax.swing.GroupLayout(ResPanel);
        ResPanel.setLayout(ResPanelLayout);
        ResPanelLayout.setHorizontalGroup(
            ResPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, ResPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(selected_responseURL, javax.swing.GroupLayout.DEFAULT_SIZE, 955, Short.MAX_VALUE)
                .addContainerGap())
            .addGroup(ResPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, ResPanelLayout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 955, Short.MAX_VALUE)
                    .addContainerGap()))
        );
        ResPanelLayout.setVerticalGroup(
            ResPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(ResPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(selected_responseURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(85, Short.MAX_VALUE))
            .addGroup(ResPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, ResPanelLayout.createSequentialGroup()
                    .addGap(47, 47, 47)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 56, Short.MAX_VALUE)
                    .addContainerGap()))
        );

        ResReqTabs.addTab(bundle.getString("ParmGenNew.ResPanel.TabConstraints.tabTitle.text"), ResPanel); // NOI18N

        TrackFromLabel.setText(bundle.getString("ParmGenNew.TrackFromLabel.text")); // NOI18N

        TrackFrom.setText("-1");

        SetToLabel.setText(bundle.getString("ParmGenNew.SetToLabel.text")); // NOI18N

        SetTo.setText("*");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(12, 12, 12)
                .addComponent(ResReqTabs))
            .addGroup(layout.createSequentialGroup()
                .addGap(16, 16, 16)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(RequestSelectBtn)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(4, 4, 4)
                        .addComponent(SaveParm)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(CancelParm)
                        .addGap(25, 25, 25))))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(ModelTabs, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jSeparator1)))
            .addGroup(layout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addComponent(TrackFromLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(TrackFrom, javax.swing.GroupLayout.PREFERRED_SIZE, 53, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(SetToLabel)
                .addGap(18, 18, 18)
                .addComponent(SetTo, javax.swing.GroupLayout.PREFERRED_SIZE, 52, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(15, 15, 15)
                .addComponent(RequestSelectBtn)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(ResReqTabs)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(TrackFromLabel)
                    .addComponent(SetToLabel)
                    .addComponent(SetTo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(TrackFrom, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(ModelTabs, javax.swing.GroupLayout.PREFERRED_SIZE, 381, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(33, 33, 33)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(SaveParm)
                    .addComponent(CancelParm))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void selected_requestURLActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_selected_requestURLActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_selected_requestURLActionPerformed

    private void NumberInitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_NumberInitActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_NumberInitActionPerformed

    private void csvFilePathActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_csvFilePathActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_csvFilePathActionPerformed

    private void jButton6ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton6ActionPerformed
        // TODO add your handling code here:
        JFileChooser jfc = new JFileChooser();
        if(jfc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            //code to handle choosed file here.
            File file = jfc.getSelectedFile();
            String name = file.getAbsolutePath().replaceAll("\\\\", "\\\\\\\\");
            csvFilePath.setText(name);
        }
    }//GEN-LAST:event_jButton6ActionPerformed

    private void csvParamAddActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_csvParamAddActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_CSVMODEL){
                return;
            }
        }
        //セッションクリア
        ParmVars.session.clear();
        ParmGenCSVLoader csvloader = new ParmGenCSVLoader(this,csvFilePath.getText());
        if(csvloader.readOneLine()){
            csvloader.setVisible(true);
        }else{
             csvloader.dispose();
        }

    }//GEN-LAST:event_csvParamAddActionPerformed

    private void CancelParmActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CancelParmActionPerformed
        // TODO add your handling code here:
        // Destroy own JFrame window.
        parentwin.refreshRowDisp(false);
        dispose();
    }//GEN-LAST:event_CancelParmActionPerformed

    private void nParamAdd4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nParamAdd4ActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_TRACKMODEL){
                return;
            }
        }
        //セッションクリア
        ParmVars.session.clear();
        //new ResponseTracker(this).setVisible(true);
       //new SelectRequest("レスポンス選択", this, new ResponseTracker(this), ParmGenNew.P_RESPONSETAB).setVisible(true);
        new SelectRequest(bundle.getString("ParmGenNew.レスポンス選択.text"), this, new ParmGenAutoTrack(this), ParmGenNew.P_RESPONSETAB).setVisible(true);
    }//GEN-LAST:event_nParamAdd4ActionPerformed

    private void numberTargetURLActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_numberTargetURLActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_numberTargetURLActionPerformed

    private void csvTargetURLActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_csvTargetURLActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_csvTargetURLActionPerformed

    private void trackTargetURLActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_trackTargetURLActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_trackTargetURLActionPerformed

    private void NumberRewindActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_NumberRewindActionPerformed
        // TODO add your handling code here:
        if (NumberRewind.isSelected()){

        }
    }//GEN-LAST:event_NumberRewindActionPerformed

    private void RequestSelectBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RequestSelectBtnActionPerformed
        // TODO add your handling code here:
        new SelectRequest(bundle.getString("ParmGenNew.リクエスト選択.text"), this, null, -1).setVisible(true);
    }//GEN-LAST:event_RequestSelectBtnActionPerformed

    private void SaveParmActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SaveParmActionPerformed
        // TODO add your handling code here:
        // 保存処理実行。
        int deftoStep = ParmVars.TOSTEPANY;
        try{
            deftoStep = Integer.parseInt(SetTo.getText());
        }catch(NumberFormatException e){
            deftoStep = ParmVars.TOSTEPANY;
        }
        if(deftoStep<0){
            deftoStep = ParmVars.TOSTEPANY;
        }
        rec.setTrackFromStep(-1);
        rec.setSetToStep(deftoStep);
        switch(current_model){
            case P_NUMBERMODEL:
                rec.setTypeValFromString(AppParmsIni.T_NUMBER_NAME);
                rec.setUrl(numberTargetURL.getText());
                rec.setLen(ParmGenUtil.parseMaxInt(NumberLen.getText()));
                if(rec.getLen()>10){
                    rec.setLen(10);
                }else if(rec.getLen()<1){
                    rec.setLen(1);
                }
                rec.setIniVal(ParmGenUtil.parseMaxInt(NumberInit.getText()));
                if(NumberRewind.isSelected()){
                    rec.updateCurrentValue(rec.getIniVal());
                }
                break;
            case P_CSVMODEL:
                rec.setTypeValFromString(AppParmsIni.T_CSV_NAME);
                rec.setUrl(csvTargetURL.getText());
                rec.crtFrl(csvFilePath.getText(), true);
                if(CSVrewind.isSelected()){
                    rec.setIniVal(ParmGenUtil.parseMinInt(CSVSkipLine.getText()));
                    rec.updateCurrentValue(rec.getIniVal());
                }
                break;
            case P_TRACKMODEL:
                rec.setTypeValFromString(AppParmsIni.T_TRACK_NAME);
                rec.setUrl(trackTargetURL.getText());
                rec.setIniVal(AppParmsIni.T_TRACK_AVCNT);
                int fromStep = -1;
                try{
                    fromStep = Integer.parseInt(TrackFrom.getText());
                }catch(NumberFormatException e){
                    fromStep = -1;
                }
                int toStep = ParmVars.TOSTEPANY;
                try{
                    toStep = Integer.parseInt(SetTo.getText());
                }catch(NumberFormatException e){
                    toStep = ParmVars.TOSTEPANY;
                }
                if(toStep<0) toStep = ParmVars.TOSTEPANY;
                rec.setTrackFromStep(fromStep);
                rec.setSetToStep(toStep);
                break;
            case P_RANDOMMODEL:
                rec.setTypeValFromString(AppParmsIni.T_RANDOM_NAME);
                break;
            default:
                break;
        }

        DefaultTableModel model = ParamTableModels[current_model];
        int rcnt = model.getRowCount();
        rec.clearAppValues();
        for(int i = 0 ; i < rcnt; i++){
            String type = (String)model.getValueAt(i, 0);
            boolean nomodify = Boolean.parseBoolean(model.getValueAt(i, 1).toString());
            String value;AppValue app = null;
            boolean increment;
            switch(current_model){
                case P_NUMBERMODEL:
                    value = (String)model.getValueAt(i, 2);
                    increment = Boolean.parseBoolean(model.getValueAt(i,3).toString());
                    app = new AppValue(type, nomodify, value, increment);
                    break;
                case P_CSVMODEL:
                    int csvpos = Integer.parseInt(model.getValueAt(i, 2).toString());
                    value = (String)model.getValueAt(i, 3);
                    increment = Boolean.parseBoolean(model.getValueAt(i,4).toString());
                    app = new AppValue(type, nomodify, csvpos, value, increment);
                    break;
                case P_TRACKMODEL:
                    value = (String)model.getValueAt(i, 2);
                    String _resURL = (String)model.getValueAt(i, 3);
                    String _resRegex = (String)model.getValueAt(i, 4);
                    String _resPartType = (String)model.getValueAt(i, 5);
                    String _resRegexPos = (String)model.getValueAt(i, 6);
                    String _token = (String)model.getValueAt(i, 7);
                    boolean _trackreq = Boolean.parseBoolean(model.getValueAt(i, 8).toString());
                    int fromStepNo = -1;
                    /***
                    try{
                        fromStepNo = (int)model.getValueAt(i, 9);
                    }catch(Exception e){
                        //
                        fromStepNo = -1;
                    }****/
                    try{
                        fromStepNo = Integer.parseInt((String)model.getValueAt(i, 9));
                    }catch(NumberFormatException e){
                        fromStepNo = -1;
                    }
                    int toStepNo = ParmVars.TOSTEPANY;
                    /***
                    try{
                        toStepNo = (int)model.getValueAt(i, 10);
                    }catch(Exception e){
                        //
                        toStepNo = 0;
                    }***/
                    try{
                        toStepNo = Integer.parseInt((String)model.getValueAt(i, 10));
                    }catch(NumberFormatException e){
                        toStepNo = ParmVars.TOSTEPANY;
                    }
                    if(toStepNo<0) toStepNo = ParmVars.TOSTEPANY;
                    int tktype;

                    String tktypename = (String)model.getValueAt(i, 11);


                    app = new AppValue(type, nomodify, value, _resURL, _resRegex, _resPartType, _resRegexPos, _token, _trackreq, fromStepNo, toStepNo,tktypename);
                    break;
                case P_RANDOMMODEL:
                    value = (String)model.getValueAt(i, 2);
                    break;
                default:
                    value = (String)model.getValueAt(i, 2);
                    break;
            }


           if(app!=null)rec.addAppValue(app);
        }
        
        if(addrec==null){
            //更新
            rec.clearLastAppValueNOCOUNT();
        }
        
        //rec.crtGenFormat(lastEntryNocount);
        
        parentwin.updateRowDisp(addrec);
        
        dispose();
        

    }//GEN-LAST:event_SaveParmActionPerformed

    private void nParamAddActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nParamAddActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_NUMBERMODEL){
                return;
            }
        }
        //セッションクリア
        ParmVars.session.clear();
        new ParmGenAddParms(this, false).setVisible(true);
    }//GEN-LAST:event_nParamAddActionPerformed

    private void NumberRegexTestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_NumberRegexTestActionPerformed
        // TODO add your handling code here
        if(current_model_selected){
            if(current_model!=P_NUMBERMODEL){
                return;
            }
        }
        int[] rowsSelected = nParamTable.getSelectedRows();
        if (rowsSelected.length > 0){
            current_tablecolidx = 2;
            current_tablerowidx = rowsSelected[0];
            new ParmGenRegex(this).setVisible(true);
        }

    }//GEN-LAST:event_NumberRegexTestActionPerformed

    private void nParamDelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nParamDelActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_NUMBERMODEL){
                return;
            }
        }
        int[] rowsSelected = nParamTable.getSelectedRows();
        if (rowsSelected.length > 0){
            current_tablerowidx = rowsSelected[0];
            ParamTableModels[P_NUMBERMODEL].removeRow(current_tablerowidx);
        }
    }//GEN-LAST:event_nParamDelActionPerformed

    private void ModelTabsStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_ModelTabsStateChanged
        // TODO add your handling code here:
        if (blockUnderInitComponents) return; // block while running initComponent
        
        int i = ModelTabs.getSelectedIndex();
        if ( i!=-1&&current_model_selected==false){
            current_model = i;
            switch(current_model){
                case P_TRACKMODEL:
                    LOGGER4J.debug("TrackFromEnabled current_model:" + i);
                    ResReqTabs.add(bundle.getString("ParmGenNew.レスポンス.text"), ResPanel);
                    ResReqTabs.setSelectedIndex(P_REQUESTTAB);
                    TrackFromLabel.setEnabled(true);
                    TrackFrom.setEnabled(true);
                    break;
                default:
                    LOGGER4J.debug("TrackFromDisabled current_model:" + i);
                    TrackFromLabel.setEnabled(false);
                    TrackFrom.setEnabled(false);
                    ResReqTabs.remove(ResPanel);
                    break;
            }
        }
    }//GEN-LAST:event_ModelTabsStateChanged

    private void nParamUPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nParamUPActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_NUMBERMODEL){
                return;
            }
        }
        int[] rowsSelected = nParamTable.getSelectedRows();
        if (rowsSelected.length > 0){
            current_tablerowidx = rowsSelected[0];
            int to = current_tablerowidx - 1;
            if ( to >= 0){
                ParamTableModels[P_NUMBERMODEL].moveRow(current_tablerowidx, current_tablerowidx, to);
            }
        }
    }//GEN-LAST:event_nParamUPActionPerformed

    private void nParamDOWNActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nParamDOWNActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_NUMBERMODEL){
                return;
            }
        }
        int[] rowsSelected = nParamTable.getSelectedRows();
        if (rowsSelected.length > 0){
            current_tablerowidx = rowsSelected[0];
            int to = current_tablerowidx + 1;
            int rowcnt = ParamTableModels[P_NUMBERMODEL].getRowCount();
            if ( to < rowcnt){
                ParamTableModels[P_NUMBERMODEL].moveRow(current_tablerowidx, current_tablerowidx, to);
            }
        }
    }//GEN-LAST:event_nParamDOWNActionPerformed

    private void selected_responseURLActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_selected_responseURLActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_selected_responseURLActionPerformed

    private void ResReqTabsStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_ResReqTabsStateChanged
        // TODO add your handling code here:
        int i = ResReqTabs.getSelectedIndex();
        if ( i!=-1){
            current_reqrespanel = i;
        }
    }//GEN-LAST:event_ResReqTabsStateChanged

    private void nParamDel12ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nParamDel12ActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_TRACKMODEL){
                return;
            }
        }
        int[] rowsSelected = trackTable.getSelectedRows();
        if (rowsSelected.length > 0){
            current_tablerowidx = rowsSelected[0];
            ParamTableModels[P_TRACKMODEL].removeRow(current_tablerowidx);
        }
    }//GEN-LAST:event_nParamDel12ActionPerformed

    private void nParamDel13ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nParamDel13ActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_TRACKMODEL){
                return;
            }
        }
        int[] rowsSelected = trackTable.getSelectedRows();
        if (rowsSelected.length > 0){
            current_tablerowidx = rowsSelected[0];
            int to = current_tablerowidx - 1;
            if ( to >= 0){
                ParamTableModels[P_TRACKMODEL].moveRow(current_tablerowidx, current_tablerowidx, to);
            }
        }
    }//GEN-LAST:event_nParamDel13ActionPerformed

    private void nParamDel14ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nParamDel14ActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_TRACKMODEL){
                return;
            }
        }
        int[] rowsSelected = trackTable.getSelectedRows();
        if (rowsSelected.length > 0){
            current_tablerowidx = rowsSelected[0];
            int to = current_tablerowidx + 1;
            int rowcnt = ParamTableModels[P_TRACKMODEL].getRowCount();
            if ( to < rowcnt){
                ParamTableModels[P_TRACKMODEL].moveRow(current_tablerowidx, current_tablerowidx, to);
            }
        }
    }//GEN-LAST:event_nParamDel14ActionPerformed

    private void jButton10ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton10ActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_TRACKMODEL){
                return;
            }
        }
        int[] rowsSelected = trackTable.getSelectedRows();
        int[] colsSelected = trackTable.getSelectedColumns();
        if (rowsSelected.length > 0){
            current_tablerowidx = rowsSelected[0];current_tablecolidx = 2;
            if (colsSelected.length > 0){
                if(colsSelected[0]>2){
                    current_tablecolidx = 4;
                }
            }
            new ParmGenRegex(this).setVisible(true);
        }
    }//GEN-LAST:event_jButton10ActionPerformed

    private void csvParamDelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_csvParamDelActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_CSVMODEL){
                return;
            }
        }
        int[] rowsSelected = csvParamTable.getSelectedRows();
        if (rowsSelected.length > 0){
            current_tablerowidx = rowsSelected[0];
            ParamTableModels[P_CSVMODEL].removeRow(current_tablerowidx);
        }
    }//GEN-LAST:event_csvParamDelActionPerformed

    private void csvParamUPActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_csvParamUPActionPerformed
        // TODO add your handling code here:
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_CSVMODEL){
                return;
            }
        }
        int[] rowsSelected = csvParamTable.getSelectedRows();
        if (rowsSelected.length > 0){
            current_tablerowidx = rowsSelected[0];
            int to = current_tablerowidx - 1;
            if ( to >= 0){
                ParamTableModels[P_CSVMODEL].moveRow(current_tablerowidx, current_tablerowidx, to);
            }
        }
    }//GEN-LAST:event_csvParamUPActionPerformed

    private void csvParamDOWNActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_csvParamDOWNActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_CSVMODEL){
                return;
            }
        }
        int[] rowsSelected = csvParamTable.getSelectedRows();
        if (rowsSelected.length > 0){
            current_tablerowidx = rowsSelected[0];
            int to = current_tablerowidx + 1;
            int rowcnt = ParamTableModels[P_CSVMODEL].getRowCount();
            if ( to < rowcnt){
                ParamTableModels[P_CSVMODEL].moveRow(current_tablerowidx, current_tablerowidx, to);
            }
        }
    }//GEN-LAST:event_csvParamDOWNActionPerformed

    private void csvParamRegexTestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_csvParamRegexTestActionPerformed
        // TODO add your handling code here:
        if(current_model_selected){
            if(current_model!=P_CSVMODEL){
                return;
            }
        }
        int[] rowsSelected = csvParamTable.getSelectedRows();
        if (rowsSelected.length > 0){
            current_tablecolidx = 3;
            current_tablerowidx = rowsSelected[0];
            new ParmGenRegex(this).setVisible(true);
        }
    }//GEN-LAST:event_csvParamRegexTestActionPerformed

    private void CSVrewindActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CSVrewindActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_CSVrewindActionPerformed

    private void NumberLenActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_NumberLenActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_NumberLenActionPerformed

    private void addTamperActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addTamperActionPerformed
        // TODO add your handling code here:
        //Tamper追加
        //セッションクリア
        ParmVars.session.clear();
        //new ParmGenAddParms(this, false).setVisible(true);
        new ParmGenTamperOpt(this).setVisible(true);
    }//GEN-LAST:event_addTamperActionPerformed

    private void upTamperActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_upTamperActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_upTamperActionPerformed

    private void delTamperActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_delTamperActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_delTamperActionPerformed

    private void downTamperActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_downTamperActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_downTamperActionPerformed

    private void modTamperActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_modTamperActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_modTamperActionPerformed

    private void NumberSelBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_NumberSelBtnActionPerformed
        // TODO add your handling code here:
        selectNumberCounterTypeCompo(AppParmsIni.NumberCounterTypes.NumberCount);

    }//GEN-LAST:event_NumberSelBtnActionPerformed

    private void DateSelBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DateSelBtnActionPerformed
        // TODO add your handling code here:
        selectNumberCounterTypeCompo(AppParmsIni.NumberCounterTypes.DateCount);
    }//GEN-LAST:event_DateSelBtnActionPerformed

    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField AddMsec;
    private javax.swing.JTextField AttackPatternFile;
    private javax.swing.JTextField CSVSkipLine;
    private javax.swing.JCheckBox CSVrewind;
    private javax.swing.JButton CancelParm;
    private javax.swing.JRadioButton DateSelBtn;
    private javax.swing.JTabbedPane ModelTabs;
    private javax.swing.JLabel MsecLabel;
    private javax.swing.JTextField NumberInit;
    private javax.swing.JTextField NumberLen;
    private javax.swing.JButton NumberRegexTest;
    private javax.swing.JCheckBox NumberRewind;
    private javax.swing.JRadioButton NumberSelBtn;
    private javax.swing.JPanel ReqPanel;
    private javax.swing.JTextPane RequestArea;
    private javax.swing.JButton RequestSelectBtn;
    private javax.swing.JPanel ResPanel;
    private javax.swing.JTabbedPane ResReqTabs;
    private javax.swing.JTextPane ResponseArea;
    private javax.swing.JButton SaveParm;
    private javax.swing.JPanel SeqCSV;
    private javax.swing.JPanel SeqNumber;
    private javax.swing.JPanel SeqRandom;
    private javax.swing.JPanel SeqResponse;
    private javax.swing.JTextField SetTo;
    private javax.swing.JLabel SetToLabel;
    private javax.swing.JLabel SimpleDateFlabel;
    private javax.swing.JTextField SimpleDateFormatStr;
    private javax.swing.JTextField TrackFrom;
    private javax.swing.JLabel TrackFromLabel;
    private javax.swing.JButton addTamper;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JTextField csvFilePath;
    private javax.swing.JButton csvParamAdd;
    private javax.swing.JButton csvParamDOWN;
    private javax.swing.JButton csvParamDel;
    private javax.swing.JButton csvParamRegexTest;
    private javax.swing.JTable csvParamTable;
    private javax.swing.JButton csvParamUP;
    private javax.swing.JTextField csvTargetURL;
    private javax.swing.JButton delTamper;
    private javax.swing.JButton downTamper;
    private javax.swing.JButton jButton10;
    private javax.swing.JButton jButton6;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JScrollPane jScrollPane5;
    private javax.swing.JScrollPane jScrollPane6;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JButton modTamper;
    private javax.swing.JButton nParamAdd;
    private javax.swing.JButton nParamAdd4;
    private javax.swing.JButton nParamDOWN;
    private javax.swing.JButton nParamDel;
    private javax.swing.JButton nParamDel12;
    private javax.swing.JButton nParamDel13;
    private javax.swing.JButton nParamDel14;
    private javax.swing.JTable nParamTable;
    private javax.swing.JButton nParamUP;
    private javax.swing.JTextField numberTargetURL;
    private javax.swing.JTextField selected_requestURL;
    private javax.swing.JTextField selected_responseURL;
    private javax.swing.JTable tamperTable;
    private javax.swing.JTextField tamperTargetURL;
    private javax.swing.JTable trackTable;
    private javax.swing.JTextField trackTargetURL;
    private javax.swing.JButton upTamper;
    // End of variables declaration//GEN-END:variables

    @Override
    public void update() {
        //NOP
    }
}
