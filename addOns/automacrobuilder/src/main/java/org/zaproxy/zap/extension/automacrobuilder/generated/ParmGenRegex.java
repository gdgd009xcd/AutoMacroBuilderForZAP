
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.Document;
import java.awt.Color;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JOptionPane;
import javax.swing.event.UndoableEditEvent;
import javax.swing.event.UndoableEditListener;
import javax.swing.text.*;
import javax.swing.undo.UndoManager;
import org.zaproxy.zap.extension.automacrobuilder.InterfaceParmGenRegexSaveCancelAction;
import org.zaproxy.zap.extension.automacrobuilder.InterfaceRegex;
import org.zaproxy.zap.extension.automacrobuilder.PRequest;
import org.zaproxy.zap.extension.automacrobuilder.PRequestResponse;
import org.zaproxy.zap.extension.automacrobuilder.PResponse;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenTextDoc;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenUtil;
import org.zaproxy.zap.extension.automacrobuilder.ParmVars;

/**
 *
 * @author tms783
 */
@SuppressWarnings("serial")
public class ParmGenRegex extends javax.swing.JDialog {

    UndoManager um;
    UndoManager original_um;
    int fidx;
    ArrayList<Integer> findplist;
    String curr_regex;
    String curr_orig;
    InterfaceRegex parentwin =null;
    InterfaceParmGenRegexSaveCancelAction regexactionwin= null;
    List<RegexSelectedTextPos> foundTextAttrPos = null;
    boolean isLabelSaveBtn = false;
    
    public static final String Escaperegex = "([\\[\\]\\{\\}\\(\\)\\*\\<\\>\\.\\?\\+\\\"\\\'\\$])";
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");
    private static  DefaultComboBoxModel<String> comboModel_regextype = null;
    private static  DefaultComboBoxModel<String> comboModel_columnpolicy = null;
    
    private void init(String regex, String orig){
        findplist.clear();
        fidx = -1;
        curr_regex = regex;
        curr_orig = orig;
    }
    
    // new される前に初期化。
    static{
        if(comboModel_regextype==null){
            comboModel_regextype = new javax.swing.DefaultComboBoxModel<String>(new String[] { 
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_regextype_number.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_regextype_number_alnum.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_regextype_number_percent.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_regextype_number_any.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_regextype_number_lfany.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_regextype_number_whitespc.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_regextype_number_jsonstr.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_regextype_number_jsonnum.text"),
            });
        }

        if(comboModel_columnpolicy==null){
            comboModel_columnpolicy = new javax.swing.DefaultComboBoxModel<String>(new String[] { 
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_fixed.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_以上（最小マッチ）.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_以上（最大マッチ）.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_以下.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_範囲.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_1以上（最小マッチ）.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_1以上（最大マッチ）.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_0以上（最小マッチ）.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_0以上（最大マッチ）.text")
            });
        }
    }
    
    /**
     * Creates new form sampleFrame
     */
    public ParmGenRegex(InterfaceRegex _parentwin, boolean showrequest) {
        initComponents();
        um = new UndoManager();
        original_um = new UndoManager();
        To.setEnabled(false);
        parentwin = _parentwin;
        regexactionwin = null;
        findplist = new ArrayList<Integer>();
        init(null, null);
        this.setModal(true);
        RegexText.setText(parentwin.getRegex());
        // OriginalText.setText(parentwin.getOriginal());
        ParmGenTextDoc reqdoc = new ParmGenTextDoc(OriginalText);
        PRequestResponse ppr = parentwin.getOriginalRequestResponse();
        if (ppr != null) {
            if (showrequest) {
                reqdoc.setRequestChunks(ppr.request);
            } else {
                reqdoc.setResponseChunks(ppr.response);
            }
        }
        OriginalText.setCaretPosition(0);
        Document rexdoc = RegexText.getDocument();
        
        foundTextAttrPos = new ArrayList<>();
        
        //RegexTextのUndo/Redo
        rexdoc.addUndoableEditListener(new UndoableEditListener() {
			public void undoableEditHappened(UndoableEditEvent e) {
				//行われた編集(文字の追加や削除)をUndoManagerに登録
				um.addEdit(e.getEdit());
			}
		});
        Document origdoc = OriginalText.getDocument();
        //RegexTextのUndo/Redo
        origdoc.addUndoableEditListener(new UndoableEditListener() {
			public void undoableEditHappened(UndoableEditEvent e) {
				//行われた編集(文字の追加や削除)をUndoManagerに登録
				original_um.addEdit(e.getEdit());
			}
		});
    }
    
    public ParmGenRegex(InterfaceParmGenRegexSaveCancelAction _actionwin, String _reg, PRequest prequest){
        initComponents();
        isLabelSaveBtn = true;
        um = new UndoManager();
        original_um = new UndoManager();
        To.setEnabled(false);
        parentwin = null;
        regexactionwin = _actionwin;
        findplist = new ArrayList<Integer>();
        init(null, null);
        this.setModal(true);
        RegexText.setText(_reg);
        // OriginalText.setText(_Original);
        ParmGenTextDoc reqdoc = new ParmGenTextDoc(OriginalText);
        reqdoc.setRequestChunks(prequest);
        OriginalText.setCaretPosition(0);
        
        foundTextAttrPos = new ArrayList<>();
        if(regexactionwin!=null){
            Save.setText(regexactionwin.getParmGenRegexSaveBtnText(isLabelSaveBtn));
            Cancel.setText(regexactionwin.getParmGenRegexCancelBtnText(isLabelSaveBtn));
        }
        
        
        //RegexTextのUndo/Redo
        Document rexdoc = RegexText.getDocument();
        rexdoc.addUndoableEditListener(new UndoableEditListener() {
			public void undoableEditHappened(UndoableEditEvent e) {
				//行われた編集(文字の追加や削除)をUndoManagerに登録
				um.addEdit(e.getEdit());
			}
		});
        //RegexTextのUndo/Redo
        Document origdoc = OriginalText.getDocument();
        origdoc.addUndoableEditListener(new UndoableEditListener() {
			public void undoableEditHappened(UndoableEditEvent e) {
				//行われた編集(文字の追加や削除)をUndoManagerに登録
				original_um.addEdit(e.getEdit());
			}
		});
    }
    
    public ParmGenRegex(InterfaceParmGenRegexSaveCancelAction _actionwin, String _reg, PResponse presponse){
        initComponents();
        isLabelSaveBtn = false;
        um = new UndoManager();
        original_um = new UndoManager();
        To.setEnabled(false);
        parentwin = null;
        regexactionwin = _actionwin;
        findplist = new ArrayList<Integer>();
        init(null, null);
        this.setModal(true);
        RegexText.setText(_reg);
        // OriginalText.setText(_Original);
        ParmGenTextDoc reqdoc = new ParmGenTextDoc(OriginalText);
        reqdoc.setResponseChunks(presponse);
        OriginalText.setCaretPosition(0);
        
        foundTextAttrPos = new ArrayList<>();
        if(regexactionwin!=null){
            Save.setText(regexactionwin.getParmGenRegexSaveBtnText(isLabelSaveBtn));
            Cancel.setText(regexactionwin.getParmGenRegexCancelBtnText(isLabelSaveBtn));
        }
        
        
        //RegexTextのUndo/Redo
        Document rexdoc = RegexText.getDocument();
        rexdoc.addUndoableEditListener(new UndoableEditListener() {
			public void undoableEditHappened(UndoableEditEvent e) {
				//行われた編集(文字の追加や削除)をUndoManagerに登録
				um.addEdit(e.getEdit());
			}
		});
        //RegexTextのUndo/Redo
        Document origdoc = OriginalText.getDocument();
        origdoc.addUndoableEditListener(new UndoableEditListener() {
			public void undoableEditHappened(UndoableEditEvent e) {
				//行われた編集(文字の追加や削除)をUndoManagerに登録
				original_um.addEdit(e.getEdit());
			}
		});
    }
    
    public static String EscapeSpecials(String _d){
        _d = _d.replaceAll(Escaperegex, "\\\\$1");
        _d = _d.replaceAll("(\r|\n)+", "(?:\\\\r|\\\\n)+?");
        return _d;
    }
    
    public static String getParsedRegexGroup(String orig, String quant){
        return "(" + getParsedRegexRaw(orig, quant) + ")";
    }
    
    public static String getParsedRegexRaw(String orig, String quant){
        String regex = orig;
        String[] patterns = new String[] {"\\d", "[a-zA-Z]", "[a-zA-Z0-9]", "[^ \t;=]",".", "[^\\<\\>]", "(?:\\s|[^\\s\\>\\<])"};
        String[] grpclose = new String[] {"+", "*"};
        for(int i = 0;i < patterns.length; i++){
            for(int j = 0 ; j< 2; j++){
                String strpattern = patterns[i] + grpclose[j];
                Pattern pattern = ParmGenUtil.Pattern_compile(strpattern);//数値
                Matcher matcher = pattern.matcher(orig); 
                if (matcher.find()){
                    regex = matcher.group();
                    if ( regex.equals(orig)){
                        int l = orig.length();
                        String result = strpattern;
                        if ( l > 0){
                            if(quant!=null&&!quant.isEmpty()){
                                result = patterns[i] + quant;
                            }else{
                                result = patterns[i] + "{" + Integer.toString(l) +"}";
                            }
                        }
                        matcher.reset();
                        return result;
                    }
                }
                matcher.reset();
            }
        }
        return  EscapeSpecials(orig) ;
    }
    
    int  hasGroupRegex(String r){
        // (?:^|[^\\])(\([^?].*?\)|\(\))
        String greg = "(?:^|[^\\\\])(\\([^?].*?\\)|\\(\\))";//後方参照グループ
        Pattern pattern = ParmGenUtil.Pattern_compile(greg);
        Matcher matcher = pattern.matcher(r);
        int gtotal = 0;
        while(matcher.find()){
            gtotal += matcher.groupCount();
        }
        return gtotal;
    }
    
    //debug printer
    private void printer(String s){
        String hex = s.replaceAll("\r", "<CR>");
        hex = hex.replaceAll("\n", "<LF>");
        
        ParmVars.plog.debuglog(1,"["+hex+"]\n");
    }
    
    private void OldSearch(){
        // TODO add your handling code here:
        SimpleAttributeSet attr = new SimpleAttributeSet();
        

        String regex = RegexText.getText();
        
        //String original = OriginalText.getText();
        Document doc = OriginalText.getDocument();
        Document blank = new DefaultStyledDocument();
        
        String original = null;
        try {
            original = doc.getText(0, doc.getLength());
        } catch (BadLocationException ex) {
            Logger.getLogger(ParmGenRegex.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        /*
        if (regex.equals(curr_regex)&&original.equals(curr_orig)){
            if (!findplist.isEmpty()){
                if(findplist.size()<=fidx){
                    fidx = 0;
                }
                OriginalText.setCaretPosition(findplist.get(fidx));
                fidx++;
                return;
            }
        }
        * */
        
        init(regex, original);
        //parse Regex
        Pattern compiledregex = null;
        Matcher m = null;
        try{
            int flags = 0;
            if(MULTILINE.isSelected()){
                flags |= Pattern.MULTILINE;
            }
            if(CASE_INSENSITIVE.isSelected()){
                flags |= Pattern.CASE_INSENSITIVE;
            }
            compiledregex = ParmGenUtil.Pattern_compile(regex, flags);
            
            m = compiledregex.matcher(original);
        }catch(Exception e){
            ParmVars.plog.printException(e);
            JOptionPane.showMessageDialog(this,bundle.getString("ParmGenRegex.正規表現が不正.text")+ e.toString() ,  bundle.getString("ParmGenRegex.正規表現エラー.text"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        
        


        try {
            doc.remove(0,doc.getLength());//remove all document..
        }catch(BadLocationException e){
            ParmVars.plog.printException(e);
        }

        OriginalText.setDocument(blank);
        
        String precontents = "";
        String postcontents = "";
        String strcnt = null;
        boolean found = false;
        int cpt = 0;
        
        int fcount=0;
        while (m.find()) {
                found = true;
                fcount++;
                int spt0 = -1;
                int ept0 = -1;
                int spt = -1;
                int ept = -1;
                int gcnt = m.groupCount();
                String matchval = null;
                if ( gcnt > 0){
                    spt0 = m.start();
                    ept0 = m.end();
                    for(int n = 0; n < gcnt ; n++){
                            spt = m.start(n+1);
                            ept = m.end(n+1);
                            matchval = m.group(n+1);

                    }
                    if ( matchval == null){
                        matchval = m.group();
                    }
                    if ( spt0 > spt){
                        spt0 = spt;
                    }
                    if(ept0 < ept){
                        ept0 = ept;
                    }
                    // spt0--->spt<matchval>ept-->ept0
                }else{//Nothing Groups...
                    spt0 = m.start();
                    ept0 = m.end();
                    matchval = m.group();
                }
                if ( spt0 >=0 && ept0 >= 0 ){
                        String prematchval = null;
                        if ( spt >= 0){
                            prematchval = original.substring(spt0, spt);
                        }
                        String postmatchval = null;
                        if( ept >= 0){
                            postmatchval = original.substring(ept, ept0);
                        }
                        precontents = original.substring(cpt, spt0) ;
                        cpt = ept0;
                        postcontents = original.substring(ept0);
                        try {
                            
                            StyleConstants.setForeground(attr, Color.BLACK);
                            StyleConstants.setBackground(attr, Color.WHITE);
                            doc.insertString(doc.getLength(), precontents, attr);
                            if ( prematchval !=null && !prematchval.isEmpty() ){
                                StyleConstants.setForeground(attr, Color.BLUE);
                                StyleConstants.setBackground(attr, Color.RED);
                                doc.insertString(doc.getLength(), prematchval, attr);
                            }
                            StyleConstants.setForeground(attr, Color.WHITE);
                            StyleConstants.setBackground(attr, Color.RED);
                            if ( matchval != null && !matchval.isEmpty()){
                                doc.insertString(doc.getLength(), matchval, attr);
                            }
                            if( postmatchval != null && !postmatchval.isEmpty()){
                                StyleConstants.setForeground(attr, Color.BLUE);
                                StyleConstants.setBackground(attr, Color.RED);
                                doc.insertString(doc.getLength(), postmatchval, attr);
                            }
                            
                            //int pos = OriginalText.getCaretPosition();
                            int pos = doc.getLength();
                            findplist.add(pos);
                            if ( fidx == -1){
                                fidx = 0;
                            }
			} catch(BadLocationException e){
                            ParmVars.plog.printException(e);
			}
                }
        }

        if ( postcontents.length() > 0 ){
            StyleConstants.setForeground(attr, Color.BLACK);
            StyleConstants.setBackground(attr, Color.WHITE);
            try{
                if ( postcontents != null && !postcontents.isEmpty()){
                    doc.insertString(doc.getLength(), postcontents, attr);
                }
            }catch(BadLocationException e){
                ParmVars.plog.printException(e);
            }
        }
        
        if ( doc.getLength()<=0 && original.length() > 0 && found == false){
            StyleConstants.setForeground(attr, Color.BLACK);
            StyleConstants.setBackground(attr, Color.WHITE);
            try{
                doc.insertString(0, original, attr);
            }catch(BadLocationException e){
                ParmVars.plog.printException(e);
            }
        }
        //jTextPaneのDocumentを更新したら、からなずsetDocumentする。
        //改行コードLFが挿入されるなど、コンテンツが不正になるので注意。
        OriginalText.setDocument(doc);
        
        if ( fidx != -1){
            OriginalText.setCaretPosition(findplist.get(fidx));
            fidx++;
            JOptionPane.showMessageDialog(this, Integer.toString(fcount)+bundle.getString("ParmGenRegex.箇所一致しました。.text"), bundle.getString("ParmGenRegex.検索結果.text"), JOptionPane.INFORMATION_MESSAGE);
        }else{
            
            java.awt.Toolkit.getDefaultToolkit().beep();
            JOptionPane.showMessageDialog(this, bundle.getString("ParmGenRegex.正規表現が一致しませんでした。.text"), bundle.getString("ParmGenRegex.検索結果.text"), JOptionPane.QUESTION_MESSAGE);
        }
    }
    
    /**
     * Seach text and set attributes OriginalText without remove contents
     * from it.
     *
     */
    private void NewSearch(){
        // TODO add your handling code here:
        SimpleAttributeSet attr = new SimpleAttributeSet();

        if (foundTextAttrPos == null) {
            foundTextAttrPos = new ArrayList<>();
        }

        String regex = RegexText.getText();

        //String original = OriginalText.getText();
        StyledDocument doc = OriginalText.getStyledDocument();
       
        if (foundTextAttrPos.size() > 0) {
            StyleConstants.setForeground(attr, Color.BLACK);
            StyleConstants.setBackground(attr, Color.WHITE);
            
            foundTextAttrPos.forEach(rpos -> {
                doc.setCharacterAttributes(rpos.getStartPos(), rpos.getEndPos() - rpos.getStartPos(), attr, false);
            });
            
            foundTextAttrPos.clear();
        }
        
        if (regex == null || regex.isEmpty()) { // if you do it, Too many patterns matched.
            return;
        }
        
        String original = null;
        try {
            original = doc.getText(0, doc.getLength());
        } catch (BadLocationException ex) {
            Logger.getLogger(ParmGenRegex.class.getName()).log(Level.SEVERE, null, ex);
        }

        init(regex, original);
        //parse Regex
        Pattern compiledregex = null;
        Matcher m = null;
        try{
            int flags = 0;
            if(MULTILINE.isSelected()){
                flags |= Pattern.MULTILINE;
            }
            if(CASE_INSENSITIVE.isSelected()){
                flags |= Pattern.CASE_INSENSITIVE;
            }
            compiledregex = ParmGenUtil.Pattern_compile(regex, flags);
            
            m = compiledregex.matcher(original);
        }catch(Exception e){
            ParmVars.plog.printException(e);
            JOptionPane.showMessageDialog(this,bundle.getString("ParmGenRegex.正規表現が不正.text")+ e.toString() ,  bundle.getString("ParmGenRegex.正規表現エラー.text"), JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        
        String precontents = "";
        String postcontents = "";
        String strcnt = null;
        boolean found = false;
        int cpt = 0;
        
        int fcount=0;
        while (m.find()) {
                found = true;
                fcount++;
                int spt0 = -1;
                int ept0 = -1;
                int spt = -1;
                int ept = -1;
                int gcnt = m.groupCount();
                String matchval = null;
                if ( gcnt > 0){
                    spt0 = m.start();
                    ept0 = m.end();
                    for(int n = 0; n < gcnt ; n++){
                            spt = m.start(n+1);
                            ept = m.end(n+1);
                            matchval = m.group(n+1);

                    }
                    if ( matchval == null){
                        matchval = m.group();
                    }
                    if ( spt0 > spt){
                        spt0 = spt;
                    }
                    if(ept0 < ept){
                        ept0 = ept;
                    }
                    // spt0--->spt<matchval>ept-->ept0
                }else{//Nothing Groups...
                    spt0 = m.start();
                    ept0 = m.end();
                    matchval = m.group();
                }
                if ( spt0 >=0 && ept0 >= 0 ){
                        
                        try {
                            
                            // spt0--->spt<matchval>ept-->ept0

                            if (ept0 > spt0) {
                                StyleConstants.setForeground(attr, Color.BLUE);
                                StyleConstants.setBackground(attr, Color.RED);
                                doc.setCharacterAttributes(spt0, ept0-spt0, attr, false);
                                RegexSelectedTextPos rpos = new RegexSelectedTextPos(spt0, ept0);
                                foundTextAttrPos.add(rpos);
                            }
                            
                            if (ept > spt) {
                                StyleConstants.setForeground(attr, Color.WHITE);
                                StyleConstants.setBackground(attr, Color.RED);
                                doc.setCharacterAttributes(spt, ept-spt, attr, false);
                                RegexSelectedTextPos rpos = new RegexSelectedTextPos(spt, ept);
                                foundTextAttrPos.add(rpos);
                            }
                            
                            //int pos = OriginalText.getCaretPosition();
                            int pos = doc.getLength();
                            findplist.add(ept0);
                            if ( fidx == -1){
                                fidx = 0;
                            }
			} catch (Exception e) {
                            ParmVars.plog.printException(e);
			}
                }
        }

        if ( fidx != -1){
            OriginalText.setCaretPosition(findplist.get(fidx));
            fidx++;
            JOptionPane.showMessageDialog(this, Integer.toString(fcount)+bundle.getString("ParmGenRegex.箇所一致しました。.text"), bundle.getString("ParmGenRegex.検索結果.text"), JOptionPane.INFORMATION_MESSAGE);
        }else{
            
            java.awt.Toolkit.getDefaultToolkit().beep();
            JOptionPane.showMessageDialog(this, bundle.getString("ParmGenRegex.正規表現が一致しませんでした。.text"), bundle.getString("ParmGenRegex.検索結果.text"), JOptionPane.QUESTION_MESSAGE);
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

        UndoRedoMenu = new javax.swing.JPopupMenu();
        Undo = new javax.swing.JMenuItem();
        Redo = new javax.swing.JMenuItem();
        OrigUndoRedoMenu = new javax.swing.JPopupMenu();
        OrigUndo = new javax.swing.JMenuItem();
        OrigRedo = new javax.swing.JMenuItem();
        jPanel1 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        RegexText = new javax.swing.JTextPane();
        jScrollPane2 = new javax.swing.JScrollPane();
        OriginalText = new javax.swing.JTextPane();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        RegexType = new javax.swing.JComboBox<>();
        jLabel3 = new javax.swing.JLabel();
        ColumnPolicy = new javax.swing.JComboBox<>();
        From = new javax.swing.JTextField();
        To = new javax.swing.JTextField();
        FTlabel = new javax.swing.JLabel();
        Add = new javax.swing.JButton();
        Save = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        Cancel = new javax.swing.JButton();
        RegexTest = new javax.swing.JButton();
        MULTILINE = new javax.swing.JCheckBox();
        CASE_INSENSITIVE = new javax.swing.JCheckBox();

        UndoRedoMenu.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                UndoRedoMenuMouseClicked(evt);
            }
            public void mousePressed(java.awt.event.MouseEvent evt) {
                UndoRedoMenuMousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                UndoRedoMenuMouseReleased(evt);
            }
        });

        Undo.setText(bundle.getString("ParmGenRegex.UNDO.text")); // NOI18N
        Undo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                UndoActionPerformed(evt);
            }
        });
        UndoRedoMenu.add(Undo);

        Redo.setText(bundle.getString("ParmGenRegex.REDO.text")); // NOI18N
        Redo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RedoActionPerformed(evt);
            }
        });
        UndoRedoMenu.add(Redo);

        OrigUndo.setText("Undo");
        OrigUndo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                OrigUndoActionPerformed(evt);
            }
        });
        OrigUndoRedoMenu.add(OrigUndo);

        OrigRedo.setText("Redo");
        OrigRedo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                OrigRedoActionPerformed(evt);
            }
        });
        OrigUndoRedoMenu.add(OrigRedo);

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle(bundle.getString("ParmGenRegex.正規表現テスト画面.text")); // NOI18N

        RegexText.setText("Formp=[^&=]*?([a-z0-9]+)[^&=]*?");
        RegexText.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                RegexTextMousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                RegexTextMouseReleased(evt);
            }
        });
        RegexText.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                RegexTextKeyPressed(evt);
            }
        });
        jScrollPane1.setViewportView(RegexText);

        OriginalText.setText("POST /travel/entry/ HTTP/1.1\nHost: 050plus-cp.com\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; ja; rv:1.9.2.23) Gecko/20110920 Firefox/3.6.23 ( .NET CLR 3.5.30729; .NET4.0E)\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\nAccept-Language: ja,en-us;q=0.7,en;q=0.3\nAccept-Encoding: gzip,deflate\nAccept-Charset: Shift_JIS,utf-8;q=0.7,*;q=0.7\nKeep-Alive: 115\nConnection: keep-alive\nReferer: https://050plus-cp.com/travel/entry/\nCookie: Formp=e70cja0sp2gcidna2baifhjp8g55kggj\nAuthorization: Basic MTEyMjozMzQ0\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 86\n\nFormp=e70cja0sp2gcidna2baifhjp8g55kggj&_mode=user_confirm&_token=&next.x=107&next.y=12");
        OriginalText.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                OriginalTextMousePressed(evt);
            }
            public void mouseReleased(java.awt.event.MouseEvent evt) {
                OriginalTextMouseReleased(evt);
            }
        });
        OriginalText.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                OriginalTextKeyPressed(evt);
            }
        });
        jScrollPane2.setViewportView(OriginalText);

        jLabel1.setText(bundle.getString("ParmGenRegex.正規表現.text")); // NOI18N

        jLabel2.setText(bundle.getString("ParmGenRegex.オリジナル.text")); // NOI18N

        RegexType.setModel(comboModel_regextype);

        jLabel3.setText(bundle.getString("ParmGenRegex.桁数.text")); // NOI18N

        ColumnPolicy.setModel(comboModel_columnpolicy);
        ColumnPolicy.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ColumnPolicyActionPerformed(evt);
            }
        });

        From.setText("1");
        From.setMinimumSize(new java.awt.Dimension(6, 22));
        From.setPreferredSize(new java.awt.Dimension(10, 22));
        From.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FromActionPerformed(evt);
            }
        });

        To.setText("10");
        To.setPreferredSize(new java.awt.Dimension(10, 22));

        FTlabel.setText(bundle.getString("ParmGenRegex.～.text")); // NOI18N

        Add.setText(bundle.getString("ParmGenRegex.追加.text")); // NOI18N
        Add.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AddActionPerformed(evt);
            }
        });

        Save.setText(bundle.getString("ParmGenRegex.保存.text")); // NOI18N
        Save.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SaveActionPerformed(evt);
            }
        });

        Cancel.setText(bundle.getString("ParmGenRegex.取消.text")); // NOI18N
        Cancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CancelActionPerformed(evt);
            }
        });

        RegexTest.setText(bundle.getString("ParmGenRegex.テスト.text")); // NOI18N
        RegexTest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RegexTestActionPerformed(evt);
            }
        });

        MULTILINE.setSelected(true);
        MULTILINE.setText(bundle.getString("ParmGenRegex.MULTILINE.text")); // NOI18N
        MULTILINE.setEnabled(false);

        CASE_INSENSITIVE.setText(bundle.getString("ParmGenRegex.英大小文字区別しない.text")); // NOI18N
        CASE_INSENSITIVE.setEnabled(false);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(5, 5, 5)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(Save)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(Cancel))
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel2)
                                    .addGroup(jPanel1Layout.createSequentialGroup()
                                        .addComponent(jLabel1)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(RegexTest)
                                        .addGap(18, 18, 18)
                                        .addComponent(MULTILINE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(CASE_INSENSITIVE)))
                                .addGap(0, 0, Short.MAX_VALUE)))
                        .addContainerGap())
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jSeparator1)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(RegexType, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(ColumnPolicy, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(From, javax.swing.GroupLayout.PREFERRED_SIZE, 37, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(FTlabel)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(To, javax.swing.GroupLayout.PREFERRED_SIZE, 45, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(Add, javax.swing.GroupLayout.PREFERRED_SIZE, 79, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(5, 5, 5))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane1))
                        .addContainerGap())))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(2, 2, 2)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(RegexTest)
                    .addComponent(MULTILINE)
                    .addComponent(CASE_INSENSITIVE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 69, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 61, Short.MAX_VALUE)
                .addGap(17, 17, 17)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(From, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(To, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(Add))
                    .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(RegexType, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jLabel3)
                        .addComponent(ColumnPolicy, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(FTlabel)))
                .addGap(7, 7, 7)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(Save)
                    .addComponent(Cancel))
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 714, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(5, 5, 5)
                    .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGap(5, 5, 5)))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 305, Short.MAX_VALUE)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addContainerGap()))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void FromActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FromActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_FromActionPerformed

    private void CancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CancelActionPerformed
        // TODO add your handling code here:
        if(regexactionwin!=null){
            regexactionwin.ParmGenRegexCancelAction(isLabelSaveBtn);
        }
        dispose();
        //setVisible(false);
    }//GEN-LAST:event_CancelActionPerformed

    private void RegexTestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RegexTestActionPerformed
        NewSearch();
    }//GEN-LAST:event_RegexTestActionPerformed

    private void AddActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_AddActionPerformed
        // TODO add your handling code here:
        String regextype_val = (String)RegexType.getSelectedItem();
        String column_policy_val = (String)ColumnPolicy.getSelectedItem();
        String from_val = From.getText();
        String to_val = To.getText();
        String regex =null;
        String regprefix = null;
        int fromI = -1;
        int toI = -1;
        
        SimpleAttributeSet attr = new SimpleAttributeSet();
        Document doc = RegexText.getDocument();
        
        String selectedtext = OriginalText.getSelectedText();
        String regexselected = RegexText.getSelectedText();
        
        boolean isselectedregex = false;
        if(regexselected!=null && !regexselected.isEmpty()){
            selectedtext = regexselected;
            isselectedregex = true;
        }

        try {
            if(from_val.length()>0)
                fromI = Integer.parseInt(from_val);
            if(to_val.length()>0)
                toI = Integer.parseInt(to_val);
        }catch(Exception e){
            if(fromI==-1)
                From.setText("");
            if(toI==-1)
                To.setText("");
            java.awt.Toolkit.getDefaultToolkit().beep();
            return;
        }

        if (regextype_val.equals(bundle.getString("ParmGenRegex.数値.text"))){
            regprefix = "\\d";
        }else if(regextype_val.equals(bundle.getString("ParmGenRegex.英数字.text"))){
            regprefix = "[0-9a-zA-Z]";
        }else if(regextype_val.equals(bundle.getString("ParmGenRegex.全角(%NN).text"))){
            regprefix = "(?:%[0-9ABCDEFabcdef]{2})";
        }else if(regextype_val.equals(bundle.getString("ParmGenRegex.任意(.*).text"))){
            regprefix = ".";
        }else if(regextype_val.equals(bundle.getString("ParmGenRegex.改行含む任意.text"))){
            regprefix = "(?:\\r|\\n|.)";
        
        }else{
            regprefix = "\\s";//ホワイトスペース（改行含む）
        }

        String minmatch = "";
        if (column_policy_val.indexOf(bundle.getString("ParmGenRegex.最小マッチ.text"))!=-1){
            minmatch = "?";
        }
        regex = ""; 
        String quant = "";
        if (column_policy_val.startsWith(bundle.getString("ParmGenRegex.以上.text")) && fromI >= 0){
            regex = new String(regprefix);
            quant = new String("{" + Integer.toString(fromI) + ",}" + minmatch);
        }else if(column_policy_val.startsWith(bundle.getString("ParmGenRegex.以下.text"))){
            regex = new String(regprefix);
            quant = new String( "{,"+ Integer.toString(fromI) + "}");
        }else if(column_policy_val.startsWith(bundle.getString("ParmGenRegex.範囲.text"))){
            regex = new String(regprefix);
            quant = new String("{"+ Integer.toString(fromI) + "," + Integer.toString(toI)+ "}");
        }else if(column_policy_val.startsWith(bundle.getString("ParmGenRegex.1以上.text"))){
            regex = new String(regprefix);
            quant = new String("+" + minmatch);
        }else if(column_policy_val.startsWith(bundle.getString("ParmGenRegex.0以上.text"))){
            regex = new String(regprefix);
            quant = new String("*" + minmatch);
        }else if(column_policy_val.startsWith(bundle.getString("ParmGenRegex.固定.text"))){
            regex = new String(regprefix);
            quant = new String("{" + Integer.toString(fromI) + "}" + minmatch);
        }else{
            regex = new String(regprefix);
            quant = new String("*" + minmatch);
        }
        regex += quant;

        if(isselectedregex){
            regex = getParsedRegexRaw(selectedtext, null);
        }
        String jsonname = "name";
        if(selectedtext!=null&&selectedtext.length()>0){
            jsonname = selectedtext;
        }
        if(regextype_val.equals(bundle.getString("ParmGenRegex.comboModel_regextype_number_jsonstr.text"))){
            regex = "\"" + jsonname + "\"(?:[\\t \\r\\n]*):(?:[\\t\\r\\n ]*)\"(.+?)\"(?:[\\t \\r\\n]*)(?:,|})";
        }else if(regextype_val.equals(bundle.getString("ParmGenRegex.comboModel_regextype_number_jsonnum.text"))){
            regex ="\"" + jsonname + "\"(?:[\\t \\r\\n]*):(?:[\\t\\r\\n ]*)([^,:{}\\\"]+?)(?:[\\t \\r\\n]*)(?:,|})";
        }
        try{
            if(isselectedregex){
                RegexText.replaceSelection(regex);
            }else{
                doc.insertString(RegexText.getCaretPosition(), regex, attr);
            }
        }catch(BadLocationException e){

        }
    }//GEN-LAST:event_AddActionPerformed

    private void ColumnPolicyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ColumnPolicyActionPerformed
        // TODO add your handling code here:
        String column_policy_val = (String)ColumnPolicy.getSelectedItem();
        
        if(column_policy_val.indexOf(bundle.getString("ParmGenRegex.範囲.text"))!=-1){
            From.setEnabled(true);
            To.setEnabled(true);
            FTlabel.setEnabled(true);
        }else if(column_policy_val.indexOf(bundle.getString("ParmGenRegex.以上.text"))!=-1||
                column_policy_val.indexOf(bundle.getString("ParmGenRegex.以下.text"))!=-1||
                column_policy_val.indexOf(bundle.getString("ParmGenRegex.固定.text"))!=-1
                ){
            From.setEnabled(true);
            To.setEnabled(false);
            FTlabel.setEnabled(false);
        }else{
            From.setEnabled(false);
            To.setEnabled(false);
            FTlabel.setEnabled(false);
        }
    }//GEN-LAST:event_ColumnPolicyActionPerformed

    private void SaveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SaveActionPerformed
        // TODO add your handling code here:
        if(regexactionwin!=null){
            regexactionwin.ParmGenRegexSaveAction(OriginalText.getStyledDocument());
            dispose();
            return;
        }
        String regex = RegexText.getText();
        int gcnt = hasGroupRegex(regex);
        if(gcnt==1){
            if(parentwin!=null){
                parentwin.setRegex(RegexText.getText());
            }
            //setVisible(false);
            dispose();
        }else if(gcnt>1){
            JOptionPane.showMessageDialog(this, bundle.getString("ParmGenRegex.正規表現にグループ指定が複数あります。.text"), bundle.getString("ParmGenRegex.正規表現エラー.text"), JOptionPane.QUESTION_MESSAGE);
        }else{
            JOptionPane.showMessageDialog(this, bundle.getString("ParmGenRegex.正規表現にグループ指定()がありません。()で置換する部分を囲んでください。.text"), bundle.getString("ParmGenRegex.正規表現エラー.text"), JOptionPane.QUESTION_MESSAGE);
        }
    }//GEN-LAST:event_SaveActionPerformed

    private void UndoRedoMenuMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_UndoRedoMenuMouseClicked
        // TODO add your handling code here:
       
    }//GEN-LAST:event_UndoRedoMenuMouseClicked

    private void UndoRedoMenuMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_UndoRedoMenuMousePressed
        // TODO add your handling code here:
        
    }//GEN-LAST:event_UndoRedoMenuMousePressed

    private void UndoRedoMenuMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_UndoRedoMenuMouseReleased
        // TODO add your handling code here:
        
    }//GEN-LAST:event_UndoRedoMenuMouseReleased

    private void RegexTextMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_RegexTextMousePressed
        // TODO add your handling code here:
         if(evt.isPopupTrigger()){
            UndoRedoMenu.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_RegexTextMousePressed

    private void RegexTextMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_RegexTextMouseReleased
        // TODO add your handling code here:
         if(evt.isPopupTrigger()){
            UndoRedoMenu.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_RegexTextMouseReleased

    private void RegexTextKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_RegexTextKeyPressed
        // TODO add your handling code here:

            switch (evt.getKeyCode()) {
            case KeyEvent.VK_Z:	//CTRL+Zのとき、UNDO実行
                    if (evt.isControlDown() && um.canUndo()) {
                            um.undo();
                            evt.consume();
                    }
                    break;
            case KeyEvent.VK_Y:	//CTRL+Yのとき、REDO実行
                    if (evt.isControlDown() && um.canRedo()) {
                            um.redo();
                    }
                    break;
            }
    }//GEN-LAST:event_RegexTextKeyPressed

    private void UndoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_UndoActionPerformed
        // TODO add your handling code here:
        if ( um.canUndo()) {
            um.undo();
        }
    }//GEN-LAST:event_UndoActionPerformed

    private void RedoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RedoActionPerformed
        // TODO add your handling code here:
        if (um.canRedo()) {
            um.redo();
        }
    }//GEN-LAST:event_RedoActionPerformed

    private void OriginalTextMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_OriginalTextMousePressed
        // TODO add your handling code here:
        if(evt.isPopupTrigger()){
            OrigUndoRedoMenu.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_OriginalTextMousePressed

    private void OriginalTextMouseReleased(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_OriginalTextMouseReleased
        // TODO add your handling code here:
        if(evt.isPopupTrigger()){
            OrigUndoRedoMenu.show(evt.getComponent(), evt.getX(), evt.getY());
        }
    }//GEN-LAST:event_OriginalTextMouseReleased

    private void OriginalTextKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_OriginalTextKeyPressed
        // TODO add your handling code here:
        switch (evt.getKeyCode()) {
            case KeyEvent.VK_Z:	//CTRL+Zのとき、UNDO実行
                    if (evt.isControlDown() && original_um.canUndo()) {
                            original_um.undo();
                            evt.consume();
                    }
                    break;
            case KeyEvent.VK_Y:	//CTRL+Yのとき、REDO実行
                    if (evt.isControlDown() && original_um.canRedo()) {
                            original_um.redo();
                    }
                    break;
            }
    }//GEN-LAST:event_OriginalTextKeyPressed

    private void OrigUndoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_OrigUndoActionPerformed
        // TODO add your handling code here:
        if ( original_um.canUndo()) {
            original_um.undo();
        }
    }//GEN-LAST:event_OrigUndoActionPerformed

    private void OrigRedoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_OrigRedoActionPerformed
        // TODO add your handling code here:
        if (original_um.canRedo()) {
            original_um.redo();
        }
    }//GEN-LAST:event_OrigRedoActionPerformed

    public static class RegexSelectedTextPos {
        int st;
        int et;
        
        RegexSelectedTextPos(int st, int et) {
            this.st = st;
            this.et = et;
        }
        
        int getStartPos() {
            return this.st;
        }
        
        int getEndPos() {
            return this.et;
        }
    
    }
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton Add;
    private javax.swing.JCheckBox CASE_INSENSITIVE;
    private javax.swing.JButton Cancel;
    private javax.swing.JComboBox<String> ColumnPolicy;
    private javax.swing.JLabel FTlabel;
    private javax.swing.JTextField From;
    private javax.swing.JCheckBox MULTILINE;
    private javax.swing.JMenuItem OrigRedo;
    private javax.swing.JMenuItem OrigUndo;
    private javax.swing.JPopupMenu OrigUndoRedoMenu;
    private javax.swing.JTextPane OriginalText;
    private javax.swing.JMenuItem Redo;
    private javax.swing.JButton RegexTest;
    private javax.swing.JTextPane RegexText;
    private javax.swing.JComboBox<String> RegexType;
    private javax.swing.JButton Save;
    private javax.swing.JTextField To;
    private javax.swing.JMenuItem Undo;
    private javax.swing.JPopupMenu UndoRedoMenu;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JSeparator jSeparator1;
    // End of variables declaration//GEN-END:variables
}
