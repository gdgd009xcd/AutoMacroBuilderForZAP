
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.generated;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.Document;
import java.awt.Color;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import javax.swing.event.UndoableEditEvent;
import javax.swing.event.UndoableEditListener;
import javax.swing.text.*;
import javax.swing.undo.UndoManager;

import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.view.*;

/**
 *
 * @author gdgd009xcd
 */
@SuppressWarnings("serial")
public class ParmGenRegex extends javax.swing.JDialog {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private final static String GROUP_OUTER_STYLENAME = "ParmGenRegex.OUTER_STYLE";
    private final static String GROUP_INNER_STYLENAME = "ParmGenRegex.INNER_STYLE";

    private final String[] styleNames = {
            GROUP_OUTER_STYLENAME,
            GROUP_INNER_STYLENAME
    };

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
    PRequest editrequest = null;
    
    CustomHttpPanelHexModel hexModel = null;
    byte[] hexdata = null;
    StyledDocumentWithChunk chunkDoc = null;
    
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
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_Or_More(lazy).text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_Or_More(greedy).text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_Or_Less_than.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_range.text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_1orMore(lazy).text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_1orMore(greedy).text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_0orMore(lazy).text"),
            java.util.ResourceBundle.getBundle("burp/Bundle").getString("ParmGenRegex.comboModel_columnpolicy_0orMore(greedy).text")
            });
        }
    }

    private void createStyles(StyledDocument doc) {
        Style defaultStyle = SwingStyle.getDefaultStyle(doc);
        if (defaultStyle == null) {
            defaultStyle = doc.getStyle(StyleContext.DEFAULT_STYLE);
        }
        for(String styleName: styleNames) {
            Style style = doc.getStyle(styleName);
            if (style == null) {
                Style newStyle = doc.addStyle(styleName, defaultStyle);
                switch (styleName) {
                    case GROUP_OUTER_STYLENAME:
                        StyleConstants.setForeground(newStyle, Color.BLUE);
                        StyleConstants.setBackground(newStyle, Color.RED);
                        break;
                    case GROUP_INNER_STYLENAME:
                        StyleConstants.setForeground(newStyle, Color.WHITE);
                        StyleConstants.setBackground(newStyle, Color.RED);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    private void removeStyles(StyledDocument doc) {
        for(String styleName: styleNames) {
            Style style = doc.getStyle(styleName);
            if (style != null) {
                doc.removeStyle(styleName);
            }
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
        JTextPaneContents reqdoc = new JTextPaneContents(OriginalText);
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
                //add edit actions to UndoManager
				um.addEdit(e.getEdit());
			}
		});
        StyledDocument origdoc = OriginalText.getStyledDocument();
        createStyles(origdoc);

        clearAllCharacterAttributesExceptPlaceHolderStyles(origdoc);

        //RegexTextのUndo/Redo
        origdoc.addUndoableEditListener(new UndoableEditListener() {
			public void undoableEditHappened(UndoableEditEvent e) {
                //add edit actions to UndoManager
				original_um.addEdit(e.getEdit());
			}
		});
    }
    
    public ParmGenRegex(InterfaceParmGenRegexSaveCancelAction _actionwin, String _reg, StyledDocumentWithChunk chunkDoc){
        initComponents();

        this.chunkDoc = chunkDoc;
        um = new UndoManager();
        original_um = new UndoManager();
        To.setEnabled(false);
        parentwin = null;
        regexactionwin = _actionwin;
        findplist = new ArrayList<Integer>();
        init(null, null);
        this.setModal(true);
        RegexText.setText(_reg);

        OriginalText.setStyledDocument(this.chunkDoc);
        createStyles(this.chunkDoc );

        clearAllCharacterAttributesExceptPlaceHolderStyles(this.chunkDoc);

        OriginalText.setCaretPosition(0);

        boolean hasBinaryContents = false;
        isLabelSaveBtn = false;


        hasBinaryContents = this.chunkDoc.hasBinaryContents();
        isLabelSaveBtn = this.chunkDoc.isRequest();
        if (isLabelSaveBtn) {
            JMenuItem insertCR = new JMenuItem(bundle.getString("ParmGenRegex.insCR.text"));
            OrigUndoRedoMenu.add(insertCR);
            insertCR.addActionListener(e -> {
                int cpos = OriginalText.getCaretPosition();
                try {
                    this.chunkDoc.insertString(cpos,"\r", this.chunkDoc.getCRstyle());
                } catch (BadLocationException badLocationException) {
                    LOGGER4J.error("", badLocationException);
                }
            });
        }

        if(hasBinaryContents) {
            RegexTest.setEnabled(false);
        }

        addHexView(isLabelSaveBtn);

        if (this.chunkDoc != null) {
            byte[] hexdata = this.chunkDoc.getBytes();
            if (hexdata != null) {
                hexModel.setData(hexdata);
            }
        }
        
        foundTextAttrPos = new ArrayList<>();
        if(regexactionwin!=null){
            Save.setText(regexactionwin.getParmGenRegexSaveBtnText(isLabelSaveBtn));
            Cancel.setText(regexactionwin.getParmGenRegexCancelBtnText(isLabelSaveBtn));
        }
        
        // Undo/Redo for RegexText
        Document rexdoc = RegexText.getDocument();
        rexdoc.addUndoableEditListener(new UndoableEditListener() {
			public void undoableEditHappened(UndoableEditEvent e) {
				//add edit actions to UndoManager
				um.addEdit(e.getEdit());
			}
		});

        // Undo/Redo for chunkdoc
        this.chunkDoc.addUndoableEditListener(new UndoableEditListener() {
			public void undoableEditHappened(UndoableEditEvent e) {
				//add edit actions to UndoManager
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
                Pattern pattern = ParmGenUtil.Pattern_compile(strpattern);// number
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
        String greg = "(?:^|[^\\\\])(\\([^?].*?\\)|\\(\\))";//back-reference group
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
        
        LOGGER4J.debug("["+hex+"]\n");
    }
    
    /**
     * Seach text and set attributes OriginalText without remove contents
     * from it.
     *
     */
    private void NewSearch(){
        // TODO add your handling code here:
        if (foundTextAttrPos == null) {
            foundTextAttrPos = new ArrayList<>();
        }

        String regex = RegexText.getText();

        //String original = OriginalText.getText();
        StyledDocument doc = OriginalText.getStyledDocument();

        clearAllCharacterAttributesExceptPlaceHolderStyles(doc);

        foundTextAttrPos.clear();

        if (regex == null || regex.isEmpty()) { // if you do it, Too many patterns matched.
            return;
        }
        
        String original = null;
        try {
            original = doc.getText(0, doc.getLength());
        } catch (BadLocationException ex) {
            LOGGER4J.error(ex.getMessage(), ex);
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
        }catch(Exception ex){
            LOGGER4J.error(ex.getMessage(), ex);
            JOptionPane.showMessageDialog(
                this,
                bundle.getString(
                        "ParmGenRegex.OptionPaneErrorMessage_RegexSyntaxError.text")
                        + ex.toString(),
                bundle.getString("ParmGenRegex.ErrorOptionPaneTitle.text"),
                JOptionPane.ERROR_MESSAGE
            );
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
                        Style outerStyle = doc.getStyle(GROUP_OUTER_STYLENAME);
                        doc.setCharacterAttributes(spt0, ept0-spt0, outerStyle, false);
                        RegexSelectedTextPos rpos = new RegexSelectedTextPos(spt0, ept0);
                        foundTextAttrPos.add(rpos);
                    }

                    if (ept > spt) {
                        Style innerStyle = doc.getStyle(GROUP_INNER_STYLENAME);
                        doc.setCharacterAttributes(spt, ept-spt, innerStyle, false);
                        RegexSelectedTextPos rpos = new RegexSelectedTextPos(spt, ept);
                        foundTextAttrPos.add(rpos);
                    }

                    //int pos = OriginalText.getCaretPosition();
                    int pos = doc.getLength();
                    findplist.add(ept0);
                    if ( fidx == -1){
                        fidx = 0;
                    }
                } catch (Exception ex) {
                    LOGGER4J.error(ex.getMessage(), ex);
                }
            }
        }

        if ( fidx != -1){
            OriginalText.setCaretPosition(findplist.get(fidx));
            fidx++;
            JOptionPane.showMessageDialog(this, Integer.toString(fcount)+bundle.getString("ParmGenRegex.SearchResultMessage.text"), bundle.getString("ParmGenRegex.SearchResultTitle.text"), JOptionPane.INFORMATION_MESSAGE);
        }else{
            
            java.awt.Toolkit.getDefaultToolkit().beep();
            JOptionPane.showMessageDialog(this, bundle.getString("ParmGenRegex.RegexMatchFailedMessage.text"), bundle.getString("ParmGenRegex.SearchResultTitle.text"), JOptionPane.QUESTION_MESSAGE);
        }
    }
    
    void addHexView(boolean editable) {
        hexModel = new CustomHttpPanelHexModel();
        hexModel.setEditable(editable);
        JTable hextable = new JTable();
        hextable.setModel(hexModel);
        JScrollPane scrollPane = new JScrollPane(hextable);
        TextTab.addTab("Hex", scrollPane);
        hextable.setGridColor(java.awt.Color.gray);
        hextable.setIntercellSpacing(new java.awt.Dimension(1, 1));

        hextable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        hextable.getColumnModel().getColumn(0).setPreferredWidth(100);
        for (int i = 1; i <= 17; i++) {
            hextable.getColumnModel().getColumn(i).setPreferredWidth(30);
        }
        for (int i = 17; i <= hextable.getColumnModel().getColumnCount() - 1; i++) {
            hextable.getColumnModel().getColumn(i).setPreferredWidth(25);
        }

        hextable.setCellSelectionEnabled(true);
        hextable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        if (editable) {
            TextTab.addChangeListener(e -> {
                int selIndex = TextTab.getSelectedIndex();//tabbedpanes selectedidx 0start..
                if (this.chunkDoc != null){
                    switch(selIndex) {
                        case 1:
                            hexdata = this.chunkDoc.getBytes();
                            hexModel.setData(hexdata);
                            break;
                        default:
                            hexdata = hexModel.getData();
                            this.chunkDoc.updateStyleDocAndChunkFromHex(hexdata);
                            OriginalText.repaint();
                            break;
                    }
                }
            });
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
        SelectPattern = new javax.swing.JMenuItem();
        jPanel1 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        RegexText = new javax.swing.JTextPane();
        TextTab = new javax.swing.JTabbedPane();
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

        java.util.ResourceBundle bundle = java.util.ResourceBundle.getBundle("burp/Bundle"); // NOI18N
        SelectPattern.setText(bundle.getString("ParmGenRegex.SelectPattern.text")); // NOI18N
        SelectPattern.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SelectPatternActionPerformed(evt);
            }
        });
        OrigUndoRedoMenu.add(SelectPattern);

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle(bundle.getString("ParmGenRegex.RegexEditorDialogTitle.text")); // NOI18N

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

        TextTab.setName("Text"); // NOI18N

        OriginalText.setText("POST /travel/entry/ HTTP/1.1\nHost: test.co\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; ja; rv:1.9.2.23) Gecko/20110920 Firefox/3.6.23 ( .NET CLR 3.5.30729; .NET4.0E)\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\nAccept-Language: ja,en-us;q=0.7,en;q=0.3\nAccept-Encoding: gzip,deflate\nAccept-Charset: Shift_JIS,utf-8;q=0.7,*;q=0.7\nKeep-Alive: 115\nConnection: keep-alive\nReferer: https://test.co/index.php\nCookie: Formp=e70cja0sp2gcidna2baifhjp8g55kggj\nContent-Type: application/x-www-form-urlencoded\nContent-Length: 86\n\nFormp=e70cja0sp2gcidna2baifhjp8g55kggj&_mode=user_confirm&_token=&next.x=107&next.y=12");
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

        TextTab.addTab("Text", jScrollPane2);

        jLabel1.setText(bundle.getString("ParmGenRegex.RegexEditorDialogLabel1.text")); // NOI18N

        jLabel2.setText(bundle.getString("ParmGenRegex.OriginalLabel2.text")); // NOI18N

        RegexType.setModel(comboModel_regextype);

        jLabel3.setText(bundle.getString("ParmGenRegex.NumOfDigitsLabel3.text")); // NOI18N

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

        FTlabel.setText(bundle.getString("ParmGenRegex.RangeFTlabel.text")); // NOI18N

        Add.setText(bundle.getString("ParmGenRegex.AddBtn.text")); // NOI18N
        Add.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                AddActionPerformed(evt);
            }
        });

        Save.setText(bundle.getString("ParmGenRegex.SaveBtn.text")); // NOI18N
        Save.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                SaveActionPerformed(evt);
            }
        });

        Cancel.setText(bundle.getString("ParmGenRegex.CancelBtn.text")); // NOI18N
        Cancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CancelActionPerformed(evt);
            }
        });

        RegexTest.setText(bundle.getString("ParmGenRegex.RegexTestBtn.text")); // NOI18N
        RegexTest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                RegexTestActionPerformed(evt);
            }
        });

        MULTILINE.setSelected(true);
        MULTILINE.setText(bundle.getString("ParmGenRegex.MULTILINE.text")); // NOI18N
        MULTILINE.setEnabled(false);

        CASE_INSENSITIVE.setText(bundle.getString("ParmGenRegex.CaseInsensitiveCheckBox.text")); // NOI18N
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
                                .addGap(0, 383, Short.MAX_VALUE)))
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
                        .addComponent(jScrollPane1)
                        .addContainerGap())))
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(TextTab, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                .addContainerGap())
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
                .addGap(18, 18, 18)
                .addComponent(TextTab, javax.swing.GroupLayout.DEFAULT_SIZE, 207, Short.MAX_VALUE)
                .addGap(18, 18, 18)
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
            .addGroup(layout.createSequentialGroup()
                .addGap(5, 5, 5)
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGap(5, 5, 5))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
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

        if (regextype_val.equals(bundle.getString("ParmGenRegex.RegexTypeNumber.text"))){
            regprefix = "\\d";
        }else if(regextype_val.equals(bundle.getString("ParmGenRegex.RegexTypeAlphanum.text"))){
            regprefix = "[0-9a-zA-Z]";
        }else if(regextype_val.equals(bundle.getString("ParmGenRegex.RegexTypeURLencoding.text"))){
            regprefix = "(?:%[0-9ABCDEFabcdef]{2})";
        }else if(regextype_val.equals(bundle.getString("ParmGenRegex.RegexTypeDotAsterisk.text"))){
            regprefix = ".";
        }else if(regextype_val.equals(bundle.getString("ParmGenRegex.RegexTypeCRLFANY.text"))){
            regprefix = "(?:\\r|\\n|.)";
        
        }else{
            regprefix = "\\s";//white space(which contains \t \r \n \f)
        }

        String minmatch = "";
        if (column_policy_val.indexOf(bundle.getString("ParmGenRegex.SelectedColumnPolicyLazy.text"))!=-1){
            minmatch = "?";
        }
        regex = ""; 
        String quant = "";
        if (column_policy_val.startsWith(bundle.getString("ParmGenRegex.SelectedColumnPolicyOrMore.text")) && fromI >= 0){
            regex = new String(regprefix);
            quant = new String("{" + Integer.toString(fromI) + ",}" + minmatch);
        }else if(column_policy_val.startsWith(bundle.getString("ParmGenRegex.SelectedColumnPolicyOrLess.text"))){
            regex = new String(regprefix);
            quant = new String( "{,"+ Integer.toString(fromI) + "}");
        }else if(column_policy_val.startsWith(bundle.getString("ParmGenRegex.SelectedColumnPolicyRange.text"))){
            regex = new String(regprefix);
            quant = new String("{"+ Integer.toString(fromI) + "," + Integer.toString(toI)+ "}");
        }else if(column_policy_val.startsWith(bundle.getString("ParmGenRegex.SelectedColumnPolicy1OrMore.text"))){
            regex = new String(regprefix);
            quant = new String("+" + minmatch);
        }else if(column_policy_val.startsWith(bundle.getString("ParmGenRegex.SelectedColumnPolicy0OrMore.text"))){
            regex = new String(regprefix);
            quant = new String("*" + minmatch);
        }else if(column_policy_val.startsWith(bundle.getString("ParmGenRegex.SelectedColumnPolicyFixed.text"))){
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
        
        if(column_policy_val.indexOf(bundle.getString("ParmGenRegex.SelectedColumnPolicyRange.text"))!=-1){
            From.setEnabled(true);
            To.setEnabled(true);
            FTlabel.setEnabled(true);
        }else if(column_policy_val.indexOf(bundle.getString("ParmGenRegex.SelectedColumnPolicyOrMore.text"))!=-1||
                column_policy_val.indexOf(bundle.getString("ParmGenRegex.SelectedColumnPolicyOrLess.text"))!=-1||
                column_policy_val.indexOf(bundle.getString("ParmGenRegex.SelectedColumnPolicyFixed.text"))!=-1
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
        if(regexactionwin!=null && this.chunkDoc != null){
            int selIndex = TextTab.getSelectedIndex();//tabbedpanes selectedidx 0start..
            if (selIndex == 1) { // hex dump view
                if (this.chunkDoc.isRequest()) {
                    hexdata = hexModel.getData();
                    this.chunkDoc.updateStyleDocAndChunkFromHex(hexdata);
                }
            }
            regexactionwin.ParmGenRegexSaveAction(this.chunkDoc);
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
            JOptionPane.showMessageDialog(this, bundle.getString("ParmGenRegex.OptionPaneErrorMessage_HasMultipleGroupRegexBrackets.text"), bundle.getString("ParmGenRegex.ErrorOptionPaneTitle.text"), JOptionPane.QUESTION_MESSAGE);
        }else{
            JOptionPane.showMessageDialog(this, bundle.getString("ParmGenRegex.OptionPaneErrorMessage_NoGroupRegexBracket.text"), bundle.getString("ParmGenRegex.ErrorOptionPaneTitle.text"), JOptionPane.QUESTION_MESSAGE);
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
            case KeyEvent.VK_Z:	//Undo when Ctrl+Z key is pressed.
                    if (evt.isControlDown() && um.canUndo()) {
                            um.undo();
                            evt.consume();
                    }
                    break;
            case KeyEvent.VK_Y:	//Undo when CTRL+Y key is pressed.
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

    private void SelectPatternActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_SelectPatternActionPerformed
        // TODO add your handling code here:
        String selected_value = OriginalText.getSelectedText();
        if (selected_value != null && !selected_value.isEmpty()) {
            String regex = "(" + selected_value + ")";
            RegexText.setText(regex);
        }
    }//GEN-LAST:event_SelectPatternActionPerformed

    private void clearAllCharacterAttributesExceptPlaceHolderStyles(StyledDocument doc) {
        if (doc instanceof StyledDocumentWithChunk) {
            StyledDocumentWithChunk docWithChunk = (StyledDocumentWithChunk) doc;
            List<InterfacePlaceHolderStyle> listOfPlaceHolderStyle = docWithChunk.getListOfPlaceHolderStyle();
            SwingStyle.clearAllCharacterAttributes(docWithChunk);
            docWithChunk.applyPlaceHolderStyle(listOfPlaceHolderStyle);
        } else {
            SwingStyle.clearAllCharacterAttributes(doc);
        }
    }

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
    private javax.swing.JMenuItem SelectPattern;
    private javax.swing.JTabbedPane TextTab;
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
