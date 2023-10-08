/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JOptionPane;
import javax.swing.text.BadLocationException;
import org.zaproxy.zap.extension.automacrobuilder.InterfaceRegex;
import org.zaproxy.zap.extension.automacrobuilder.PRequestResponse;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenGSONSaveV2;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenSession;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenTextDoc;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenUtil;
import org.zaproxy.zap.extension.automacrobuilder.ParmVars;
import org.zaproxy.zap.extension.automacrobuilder.StrSelectInfo;
import org.zaproxy.zap.extension.automacrobuilder.interfaceParmGenWin;



/**
 *
 * @author tms783
 */
@SuppressWarnings("serial")
public class ResponseTracker extends javax.swing.JFrame implements InterfaceRegex, interfaceParmGenWin {

    private static org.apache.logging.log4j.Logger LOGGER4J = org.apache.logging.log4j.LogManager.getLogger();

    ParmGenNew parentwin;
    
    public static final int T_NAME = 0;
    public static final int T_VALUE = 1;
    public static final int T_OPTIONTITLE = 2;
    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    PRequestResponse currentrequestresponse = null;
    
    // 正規表現適用順序
    // 0-8 
    // end of array == -1 
    int REXSEQ[] ={
      7,8,0,1,2,3,4,5,6,-1  
    };
    
    int matchpos; 
    int headerlength;
    String regexpattern;
    String respart;
    boolean isheader;
    
    /**
     * Creates new form ResponseTracker
     */
    public ResponseTracker(ParmGenNew _pwin) {
        parentwin = _pwin;
        // initComponents();
        customInitComponents();
        matchpos = -1;
        regexpattern = null;
        respart = "responsebody";
        isheader = false;
        
    }
    
    public String getRegex(){
        return RegexPattern.getText();
    }
    
    public String getOriginal(){
        return ResponseArea.getText();
    }
    
    public void setRegex(String regex){
        regexpattern = regex;
        RegexPattern.setText(regexpattern);
    }
    
   
    
    /*
     * 選択領域直前の<>タグ
     */
    private StrSelectInfo getSelectionPrefixRegex(StrSelectInfo ssinfo) {
        int startpos = ResponseArea.getSelectionStart();
        int lfcnt=0;
        int tagcnt = 0;
        int tagbgn = -1;
        int lbgn = -1;
        for(int i = startpos; i>=0 ; i--){
            int offs = i;
            try{
                String ch = ResponseArea.getText(offs, 1);
                char c = ch.charAt(0);
                switch(c){
                    case '\n':
                        lfcnt++;
                        break;
                    case '>':
                        if (tagcnt==0){
                            tagcnt = 1;
                        }
                        break;
                    case '<':
                        if(tagcnt==1){
                            tagcnt = 2;
                            tagbgn = offs;
                        }
                        break;
                    default:
                        break;
                }
                if (lfcnt>1){
                    break;
                }
                lbgn = offs;
            }catch(BadLocationException e){
                ParmVars.plog.printException(e);
            }
        }
        
        // lbgn < tagbgn < startpos
        if ( tagbgn > -1){
            try {
                ssinfo.val = ResponseArea.getText(tagbgn, startpos - tagbgn);
                ssinfo.start = tagbgn;
                ssinfo.end = startpos;
                return ssinfo;
            } catch (BadLocationException ex) {
                Logger.getLogger(ResponseTracker.class.getName()).log(Level.SEVERE, null, ex);
            }
        }else if(lbgn > -1){
            try {
                ssinfo.val = ResponseArea.getText(lbgn, startpos - lbgn);
                ssinfo.start = lbgn;
                ssinfo.end = startpos;
                return ssinfo;
            } catch (BadLocationException ex) {
                Logger.getLogger(ResponseTracker.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }
    
    /*
     * 選択領域直後の<>タグ
     */
    private StrSelectInfo getSelectionSuffixRegex(StrSelectInfo ssinfo){
        int endpos = ResponseArea.getSelectionEnd();
        int lastpos = ResponseArea.getText().length();
        int lfcnt=0;
        int tagcnt = 0;
        int tagend = -1;
        int lend = -1;
        for(int i = endpos; i<lastpos ; i++){
            int offs = i;
            try{
                String ch = ResponseArea.getText(offs, 1);
                char c = ch.charAt(0);
                switch(c){
                    case '\n':
                        lfcnt++;
                        break;
                    case '<':
                        if (tagcnt==0){
                            tagcnt = 1;
                        }
                        break;
                    case '>':
                        if(tagcnt==1){
                            tagcnt = 2;
                            tagend = offs;
                        }
                        break;
                    default:
                        break;
                }
                if (lfcnt>1){
                    break;
                }
                lend = offs;
            }catch(BadLocationException e){
                ParmVars.plog.printException(e);
            }
        }
        
        // endpos < tagend < lend
        if ( tagend > -1){
            try {
                ssinfo.val = ResponseArea.getText(endpos, tagend - endpos+1);
                ssinfo.start = endpos;
                ssinfo.end = tagend;
                return ssinfo;
            } catch (BadLocationException ex) {
                Logger.getLogger(ResponseTracker.class.getName()).log(Level.SEVERE, null, ex);
            }
        }else if(lend > -1){
            try {
                ssinfo.val = ResponseArea.getText(endpos, lend - endpos+1);
                ssinfo.start = endpos;
                ssinfo.end = lend;
                return ssinfo;
            } catch (BadLocationException ex) {
                Logger.getLogger(ResponseTracker.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }
    
    private boolean isMatched(int i, int s, int e, String regex, String reqstr, ArrayList<String> groupvalues, boolean first){
        Pattern pattern = ParmGenUtil.Pattern_compile(regex,Pattern.CASE_INSENSITIVE|Pattern.MULTILINE);
        Matcher matcher;
        matchpos = -1;
        try{
            String trueregex = null;
            matcher = pattern.matcher(reqstr);
            while(matcher.find()){
                matchpos++;
                groupvalues.clear();
                int gcnt = matcher.groupCount();
                if ( gcnt > 0){
                    int valuepos;
                    switch (i){
                        case 0://<input name="(g1)" value="(g2)">
                            valuepos = gcnt;
                            if(gcnt>1){
                                groupvalues.add(matcher.group(1));
                                groupvalues.add(matcher.group(2));
                                groupvalues.add("");
                            }else{
                                groupvalues.add("");
                                groupvalues.add(matcher.group(1));
                                groupvalues.add("");
                            }
                            break;
                        case 1://<option value="(1 val)">(2optiontitle)</option>
                        case 7://<option value="(1 val)" selected>(2optiontitle)</option>
                        case 8://<option selected value="(1 val)">(2optiontitle)</option>
                            valuepos = 1;
                            if(gcnt>1){
                                groupvalues.add("");
                                groupvalues.add(matcher.group(1));
                                groupvalues.add(matcher.group(2));
                            }else{
                                groupvalues.add("");
                                groupvalues.add("");
                                groupvalues.add("");
                            }
                            break;
                        case 2:
                            valuepos = gcnt;
                            if(gcnt>2){
                                valuepos = 2;
                                groupvalues.add(matcher.group(1));
                                groupvalues.add(matcher.group(2));
                                groupvalues.add(matcher.group(3));
                            }else{
                                groupvalues.add("");
                                groupvalues.add("");
                                groupvalues.add("");
                            }
                            break;
                        case 3://<(1 tagname)>(2value)<xxx>
                        case 4:
                            valuepos = gcnt;
                            if(gcnt>1){
                                groupvalues.add(matcher.group(1));
                                groupvalues.add(matcher.group(2));
                                groupvalues.add("");
                            }else{
                                groupvalues.add("");
                                groupvalues.add("");
                                groupvalues.add("");
                            }
                            break;
                        case 5:
                        case 6:
                            valuepos = gcnt;
                            if(gcnt>1){
                                groupvalues.add(matcher.group(1));
                                groupvalues.add(matcher.group(2));
                                groupvalues.add("");
                            }else{
                                groupvalues.add("");
                                groupvalues.add("");
                                groupvalues.add("");
                            }
                            break;
                        default:
                            valuepos = gcnt;
                            groupvalues.add(matcher.group(1));
                            break;
                    }
                    int _s = matcher.start(valuepos);
                    int _e = matcher.end(valuepos);
                    
                    if (isheader){
                        if (_s > headerlength){
                            matcher.reset();
                            break;
                        }
                    }
                    if ( _s == s && _e == e){
                        matcher.reset();
                        return true;
                    }
                }
                if(first){
                    matcher.reset();
                    break;
                }
            }
            matcher.reset();

        }catch(Exception err){
            LOGGER4J.error("", err);
        }
        return false;
    }
    
    private String getNameVal(int i){
        switch(i){
            case 3:
                return "(\\s|[^\\<\\>]*?)";
            case 5:
                return "([^\\<\\>:]*?(?:[ \\t]*?):(?:[ \\t]*?)(?:.*)[0-9A-Za-z_\\-\\.]+=)";//header: name=value...
            case 6:
                return "([^\\<\\>:]*?(?:[ \\t]*?):(?:[ \\t]*?)(?:.*))";//header: value...
            default:
                break;
        }
        return "(.*?)";
    }
    
    private String getOptionVal(int i){
        switch(i){
            case 2:
                return "(.*)";
            default:
                break;
        }
        return "(\\s|[^\\s\\>\\<]*?)";//改行含むメニュータイトル
    }
    
    private String getInputTagRegex(int i,  String nameval, String optiontitle, String val, String realval){
        switch(i){
            case 0:
                //return  "\\<input(?:[ \\t]+)(?:.*?)name(?:[ \\t]*?)=(?:[ \\t]*?)\"" + nameval + "\"(?:.*?)value(?:[ \\t]*?)=(?:[ \\t]*?)\"" + val + "\"" ;
                return  "\\<input(?:.*?)name(?:[ \\t]*?)=(?:[ \\t]*?)\"" + nameval + "\"(?:.*?)value(?:[ \\t]*?)=(?:[ \\t]*?)\"" + val + "\"" ;
            case 1://option tag
                return  "\\<option(?:.*?)value(?:[ \\t]*?)=(?:[ \\t]*?)\""+ val +"\"(?:.*?)\\>" + optiontitle + "\\</option\\>";
                //return "\\<select(?:[ \\t]+)(?:.*?)name(?:[ \\t]*?)=(?:[ \\t]*?)\""+ nameval +"\"(?:.*?)\\>(?:\\s|[^\\s])*?<option(?:[ \\t]*?)*?value(?:[ \\t]*?)=(?:[ \\t]*?)\"" + val + "\"(?:.*?)>" + optiontitle + "\\</option\\>";
            case 2:
                return "^"+ nameval + "(?:\"|\\>)" + realval + "(?:\"|\\<)" + optiontitle + "$";
            case 3:
                return "\\<"+ nameval + "\\>" + val + "\\<[^\\<\\>]+\\>";
            case 4:
                return "\\<"+ nameval + "\\>" + val + "$";//改行終了
            case 5 :
                return "^" + nameval +  val + "(?:[ \t;]*?)" + ".*$";
            case 6 :
                return "^" + nameval +  val +  ".*$";
            case 7://<option value="(val)" selected>optiontitle</option>
                return  "\\<option(?:.*?)value(?:[ \\t]*?)=(?:[ \\t]*?)\""+ val +"\"(?:.*?)selected(?:.*?)\\>" + optiontitle + "\\</option\\>";
            case 8://<option selected value="(val)">optiontitle</option>
                return  "\\<option(?:.*?)selected(?:.*?)value(?:[ \\t]*?)=(?:[ \\t]*?)\""+ val +"\"(?:.*?)\\>" + optiontitle + "\\</option\\>";
            default:
                break;
        }
        return null;
    }
 
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        RegexTextBtn = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        ResponseURL = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        RegexPattern = new javax.swing.JTextField();
        jButton2 = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        jButton3 = new javax.swing.JButton();
        jButton4 = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        FixedValue = new javax.swing.JCheckBox();
        jScrollPane1 = new javax.swing.JScrollPane();
        ResponseArea = new javax.swing.JTextPane();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle(bundle.getString("ResponseTracker.ExtractTrackingParamTitle.text")); // NOI18N

        RegexTextBtn.setText(bundle.getString("ResponseTracker.RegexTextBtn.text")); // NOI18N
        RegexTextBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RegexTextBtnActionPerformed(evt);
            }
        });

        jLabel1.setText(bundle.getString("ResponseTracker.InstructionDescLabel1.text")); // NOI18N
        jLabel1.setVerticalAlignment(javax.swing.SwingConstants.TOP);

        ResponseURL.setText("jTextField1");

        jLabel2.setText(bundle.getString("ResponseTracker.URL.text")); // NOI18N

        jButton2.setText(bundle.getString("ResponseTracker.SelectValue.text")); // NOI18N
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jButton3.setText(bundle.getString("ResponseTracker.NextBtn3.text")); // NOI18N
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jButton4.setText(bundle.getString("ResponseTracker.CancelBtn4.text")); // NOI18N
        jButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton4ActionPerformed(evt);
            }
        });

        jLabel3.setText(bundle.getString("ResponseTracker.ResponseLabel3.text")); // NOI18N

        FixedValue.setText(bundle.getString("ResponseTracker.FixedValueCheckBox.text")); // NOI18N

        jScrollPane1.setViewportView(ResponseArea);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel2)
                        .addGap(58, 58, 58)
                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                        .addContainerGap())
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jSeparator1)
                        .addContainerGap())
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jButton3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jButton4))
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE, 163, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(18, 18, 18)
                                        .addComponent(FixedValue))
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(RegexPattern, javax.swing.GroupLayout.PREFERRED_SIZE, 488, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(18, 18, 18)
                                        .addComponent(RegexTextBtn)))
                                .addGap(0, 345, Short.MAX_VALUE)))
                        .addGap(12, 12, 12))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addContainerGap(931, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jScrollPane1)
                            .addComponent(ResponseURL))
                        .addContainerGap())))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jLabel2)
                    .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 52, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(ResponseURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(14, 14, 14)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 194, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton2)
                    .addComponent(FixedValue))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(RegexPattern, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(RegexTextBtn))
                .addGap(18, 18, 18)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton3)
                    .addComponent(jButton4))
                .addGap(22, 22, 22))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    public void update(){
        if ( ParmGenGSONSaveV2.selected_messages.size()>0){
            PRequestResponse rs = ParmGenGSONSaveV2.selected_messages.get(0);
            currentrequestresponse = rs;
            ResponseURL.setText(rs.request.getURL());
            ParmGenTextDoc rdoc = new ParmGenTextDoc(ResponseArea);
            rdoc.setResponseChunks(rs.response);
            ResponseArea.setCaretPosition(0);   
            headerlength = Integer.parseInt(ParmVars.session.get(ParmGenSession.K_HEADERLENGTH));
        }
    }
    private void jButton4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton4ActionPerformed
        // TODO add your handling code here:
        dispose();
    }//GEN-LAST:event_jButton4ActionPerformed

    private void jButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton2ActionPerformed
        // TODO add your handling code here:
        String selected_value = ResponseArea.getSelectedText();
        String trimmed = selected_value.trim();
        int offset = selected_value.length() - trimmed.length();
        selected_value = trimmed;
        int startpos = ResponseArea.getSelectionStart();
        int endpos = ResponseArea.getSelectionEnd()-offset;
        String reqstr = ResponseArea.getText();
        
        String quant = null;
        if(!FixedValue.isSelected()){
            quant = "+";
        }
        if(startpos < headerlength && endpos >= headerlength){
            JOptionPane.showMessageDialog(this,"<HTML>header～bodyにまたがる範囲選択はできません。<BR>header/bodyどちらか一方を選択してください。</HTML>" ,  "範囲選択エラー", JOptionPane.ERROR_MESSAGE);
            return;
        }
        // headerlength == until response... headersCRLF...CRLFCRLF
        if (endpos > headerlength){
            ParmVars.plog.AppendPrint("body endpos:" + Integer.toString(endpos) + " hlen:" + Integer.toString(headerlength));
            respart = "responsebody";
            isheader = false;
        }else{
            ParmVars.plog.AppendPrint("header endpos:" + Integer.toString(endpos) + " hlen:" + Integer.toString(headerlength));
            respart ="header";
            isheader = true;
        }
        matchpos = -1;
        regexpattern = null;
        String regex = "(.*?)";//空値
        String realval = "()";
        if ( startpos >=0 && startpos < endpos ){
            regex = ParmGenRegex.getParsedRegexGroup(selected_value, quant);
            realval = "(" + ParmGenRegex.EscapeSpecials(selected_value) + ")";
        }
       
        //<input ... name="xxx" value="">
        int i = 0;
        String inputtagregex;
        String optiontitle = getOptionVal(i);
        String nameval = getNameVal(i);
        boolean hasHREF = false;
        ArrayList<String> groupvalues = new ArrayList<String>();
        while((inputtagregex = getInputTagRegex(REXSEQ[i], nameval, optiontitle, regex, realval))!=null){
            ParmVars.plog.AppendPrint(Integer.toString(REXSEQ[i]) +":[" + inputtagregex + "]");
            groupvalues.clear();
            if (isMatched(REXSEQ[i],startpos, endpos, inputtagregex, reqstr, groupvalues, false)){
                ParmVars.plog.AppendPrint("matched...");
                Iterator<String> it = groupvalues.iterator();
                if(it.hasNext()){
                    String rawnameval = groupvalues.get(ResponseTracker.T_NAME);
                    String rawoptiontitle = groupvalues.get(ResponseTracker.T_OPTIONTITLE);
                    rawnameval = ParmGenRegex.EscapeSpecials(rawnameval);
                    String lowerval = rawnameval.toLowerCase();
                    if(lowerval.contains("href")){//hrefリンクはマッチしない。
                        hasHREF = true;
                        break;
                    }
                    rawoptiontitle = ParmGenRegex.EscapeSpecials(rawoptiontitle);
                    String rawval = groupvalues.get(ResponseTracker.T_VALUE);
                    String parsedregex = ParmGenRegex.getParsedRegexGroup(rawval, quant);
                    ParmVars.plog.AppendPrint("rawnameval[" + rawnameval + "] rawoptiontitle[" + rawoptiontitle + "] rawval[" + rawval + "] regex[" + parsedregex + "]");
                    groupvalues.clear();
                    inputtagregex = getInputTagRegex(REXSEQ[i], rawnameval, rawoptiontitle, regex, parsedregex);
                    ParmVars.plog.AppendPrint(inputtagregex);
                    if (isMatched(REXSEQ[i],startpos, endpos, inputtagregex, reqstr, groupvalues, false)){
                        ParmVars.plog.AppendPrint("matched validregex[" + inputtagregex + "]");
                        regexpattern = inputtagregex;
                        RegexPattern.setText(regexpattern);
                        break;
                    }
                }
            }
            i++;
            nameval = getNameVal(REXSEQ[i]);
            optiontitle = getOptionVal(REXSEQ[i]);
        }
        if (regexpattern==null && startpos >=0 && startpos < endpos){//任意の選択パターン
            StrSelectInfo prefix = new StrSelectInfo();
            StrSelectInfo suffix = new StrSelectInfo();
            prefix=getSelectionPrefixRegex(prefix);
            suffix=getSelectionSuffixRegex(suffix);
            if(hasHREF){
                inputtagregex = ParmGenUtil.getPathsRegex(selected_value);
            }else{
                inputtagregex = ParmGenRegex.getParsedRegexGroup(selected_value, quant);
            }
            if(prefix!=null&&startpos!=headerlength){//開始位置＝＝body開始の場合は、prefix無し。
                    inputtagregex = ParmGenRegex.EscapeSpecials(prefix.val) + inputtagregex;
            }
            if(suffix!=null){
                inputtagregex += ParmGenRegex.EscapeSpecials(suffix.val);
            }
            //inputtagregex = "(" + EscapeSpecials(selected_value) + ")";
            
            ParmVars.plog.AppendPrint("any tag[" + inputtagregex + "]");
            if (isMatched(99,startpos, endpos, inputtagregex, reqstr, groupvalues, false)){
                ParmVars.plog.AppendPrint("matched any pattern validregex[" + inputtagregex + "]");
                regexpattern = inputtagregex;
                RegexPattern.setText(regexpattern);
            }else{
                String selected_value_escaped  = selected_value.replaceAll("(\r|\n)+", "(?:\\\\r|\\\\n)+?");
                regexpattern = "(" + selected_value_escaped + ")";
                RegexPattern.setText(regexpattern);
            }
        }
      

    }//GEN-LAST:event_jButton2ActionPerformed

    private void RegexTextBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_RegexTextBtnActionPerformed
        // TODO add your handling code here:
        new ParmGenRegex(this, false).setVisible(true);
    }//GEN-LAST:event_RegexTextBtnActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        // TODO add your handling code here:
        if ( currentrequestresponse == null ) return;
        ParmVars.session.put(ParmGenSession.K_RESPONSEREGEX, regexpattern);
        ParmVars.session.put(ParmGenSession.K_RESPONSEPART, respart);
       
        int mcnt = ParmGenUtil.getRegexMatchpos(getRegex(), currentrequestresponse.response.getMessage());
        String poscnt = null;
        
        if(mcnt>0){
            poscnt = Integer.toString(mcnt-1);
        }
        if(poscnt!=null){
            ParmVars.session.put(ParmGenSession.K_RESPONSEPOSITION, poscnt);
            dispose();
            new SelectRequest(bundle.getString("ResponseTracker.SelectRequestTitle.text"), parentwin, new ParmGenAddParms(parentwin, true), ParmGenNew.P_REQUESTTAB).setVisible(true);
        }else{
            JOptionPane.showMessageDialog(this,"<HTML>正規表現に誤りがあります。</HTML>" ,  "正規表現エラー", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_jButton3ActionPerformed

    private void customInitComponents() {

        RegexTextBtn = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jLabel1.putClientProperty("html.disable", Boolean.FALSE);
        ResponseURL = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        RegexPattern = new javax.swing.JTextField();
        jButton2 = new javax.swing.JButton();
        jSeparator1 = new javax.swing.JSeparator();
        jButton3 = new javax.swing.JButton();
        jButton4 = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        FixedValue = new javax.swing.JCheckBox();
        jScrollPane1 = new javax.swing.JScrollPane();
        ResponseArea = new javax.swing.JTextPane();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle(bundle.getString("ResponseTracker.ExtractTrackingParamTitle.text")); // NOI18N

        RegexTextBtn.setText(bundle.getString("ResponseTracker.RegexTextBtn.text")); // NOI18N
        RegexTextBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RegexTextBtnActionPerformed(evt);
            }
        });

        jLabel1.setText(bundle.getString("ResponseTracker.InstructionDescLabel1.text")); // NOI18N
        jLabel1.setVerticalAlignment(javax.swing.SwingConstants.TOP);

        ResponseURL.setText("jTextField1");

        jLabel2.setText(bundle.getString("ResponseTracker.URL.text")); // NOI18N

        jButton2.setText(bundle.getString("ResponseTracker.SelectValue.text")); // NOI18N
        jButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton2ActionPerformed(evt);
            }
        });

        jButton3.setText(bundle.getString("ResponseTracker.NextBtn3.text")); // NOI18N
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jButton4.setText(bundle.getString("ResponseTracker.CancelBtn4.text")); // NOI18N
        jButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton4ActionPerformed(evt);
            }
        });

        jLabel3.setText(bundle.getString("ResponseTracker.ResponseLabel3.text")); // NOI18N

        FixedValue.setText(bundle.getString("ResponseTracker.FixedValueCheckBox.text")); // NOI18N

        jScrollPane1.setViewportView(ResponseArea);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(jLabel2)
                                                .addGap(58, 58, 58)
                                                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                                                .addContainerGap())
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(jSeparator1)
                                                .addContainerGap())
                                        .addGroup(layout.createSequentialGroup()
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(layout.createSequentialGroup()
                                                                .addComponent(jButton3)
                                                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                                                .addComponent(jButton4))
                                                        .addGroup(layout.createSequentialGroup()
                                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                                        .addGroup(layout.createSequentialGroup()
                                                                                .addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE, 163, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                .addGap(18, 18, 18)
                                                                                .addComponent(FixedValue))
                                                                        .addGroup(layout.createSequentialGroup()
                                                                                .addComponent(RegexPattern, javax.swing.GroupLayout.PREFERRED_SIZE, 488, javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                .addGap(18, 18, 18)
                                                                                .addComponent(RegexTextBtn)))
                                                                .addGap(0, 345, Short.MAX_VALUE)))
                                                .addGap(12, 12, 12))
                                        .addGroup(layout.createSequentialGroup()
                                                .addComponent(jLabel3)
                                                .addContainerGap(931, Short.MAX_VALUE))
                                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addComponent(jScrollPane1)
                                                        .addComponent(ResponseURL))
                                                .addContainerGap())))
        );
        layout.setVerticalGroup(
                layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                        .addComponent(jLabel2)
                                        .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 52, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(18, 18, 18)
                                .addComponent(ResponseURL, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(14, 14, 14)
                                .addComponent(jLabel3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 194, Short.MAX_VALUE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jButton2)
                                        .addComponent(FixedValue))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(RegexPattern, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addComponent(RegexTextBtn))
                                .addGap(18, 18, 18)
                                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(jButton3)
                                        .addComponent(jButton4))
                                .addGap(22, 22, 22))
        );

        pack();
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox FixedValue;
    private javax.swing.JTextField RegexPattern;
    private javax.swing.JButton RegexTextBtn;
    private javax.swing.JTextPane ResponseArea;
    private javax.swing.JTextField ResponseURL;
    private javax.swing.JButton jButton2;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JSeparator jSeparator1;
    // End of variables declaration//GEN-END:variables

    @Override
    public void updateMessageAreaInSelectedModel(int panel) {
        //NOP
    }

    @Override
    public PRequestResponse getOriginalRequestResponse() {
        return currentrequestresponse;
    }
}
