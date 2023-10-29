/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.automacrobuilder.view;

import org.zaproxy.zap.extension.automacrobuilder.PRequest;
import org.zaproxy.zap.extension.automacrobuilder.PResponse;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenUtil;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;
import javax.swing.text.StyledDocument;

/** @author youtube */
public class JTextPaneContents {

    private JTextPane tcompo;
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public JTextPaneContents(JTextPane tc) {
        init();
        tcompo = tc;
    }

    private void init() {
        tcompo = null;
    }

    void setdatadoc() {
        JTextComponent editor = tcompo;
        String filestring = "";
        byte[] b = new byte[4096];
        int readByte = 0, totalByte = 0;
        try {
            DataInputStream dataInStream =
                    new DataInputStream(
                            new BufferedInputStream(new FileInputStream("C:\\temp\\bindata.txt")));
            // File rfile = new File("C:\\temp\\text.jpg");
            while (-1 != (readByte = dataInStream.read(b))) {
                try {
                    filestring = filestring + new String(b, "ISO8859-1");
                } catch (UnsupportedEncodingException e) {
                    filestring += "unsupported.\n";
                }
                totalByte += readByte;
                // System.out.println("Read: " + readByte + " Total: " + totalByte);
            }
        } catch (IOException ex) {
            // Logger.getLogger(NewJFrame.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("before LFinsert");
        // filestring = filestring.substring(0, 1024);
        String display = ParmGenUtil.LFinsert(filestring);
        System.out.println("LFinsert done. before reader");
        Document blank = new DefaultStyledDocument();
        Document doc = editor.getDocument();
        editor.setDocument(blank);
        try {
            // Editor.setPage(rfile.toURI().toURL());

            doc.insertString(0, display, null);

            editor.setDocument(doc);
            // TextArea.setText(filestring);
            // Editor.setText(filestring);

        } catch (Exception ex) {
            // Logger.getLogger(NewJFrame.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    void save(byte[] bindata) {

        if (bindata == null) return;

        // ファイルオブジェクト作成
        FileOutputStream fileOutStm = null;
        try {
            fileOutStm = new FileOutputStream("E:\\kkk\\bindata.txt");
        } catch (FileNotFoundException e1) {
            // System.out.println("ファイルが見つからなかった。");
        }
        try {
            fileOutStm.write(bindata);
        } catch (IOException e) {
            // System.out.println("入出力エラー。");
        }
        // System.out.println("終了");
    }

    public void setText(String text) {
        StyledDocument doc = null;
        if (tcompo != null) {
            StyledDocument blank = new DefaultStyledDocument();

            // if you change or newly create Document in JEditorPane's Document, JEditorPane cannot
            // display contents. this problem occur only ZAP.
            // Thus you must get original Document from JEditorPane for Setting Text.
            doc = tcompo.getStyledDocument();

            tcompo.setDocument(blank);
            try {
                LOGGER4J.debug("before  remove text");
                doc.remove(0, doc.getLength());
                LOGGER4J.debug("done remove text");
            } catch (BadLocationException ex) {
                Logger.getLogger(JTextPaneContents.class.getName()).log(Level.SEVERE, null, ex);
            }

            try {
                LOGGER4J.debug("before  insert text size=" + text.length());
                doc.insertString(0, text, null);
                LOGGER4J.debug("insert  done");
            } catch (BadLocationException ex) {
                Logger.getLogger(JTextPaneContents.class.getName()).log(Level.SEVERE, null, ex);
            }
            LOGGER4J.debug("before setDocument");
            tcompo.setDocument(doc);
            LOGGER4J.debug("after setDocument");
        }
    }

    /**
     * Set request contents. large binary data representation is image icon.
     *
     * @param prequest
     */
    public void setRequestChunks(PRequest prequest) {

        if (tcompo == null) return;
        StyledDocument blank = new DefaultStyledDocument();

        // if you change or newly create Document in JEditorPane's Document, JEditorPane cannot
        // display contents. this problem occur only ZAP.
        // Thus you must get original Document from JEditorPane for Setting Text.
        tcompo.setStyledDocument(blank);


        StyledDocumentWithChunk requestdoc = new StyledDocumentWithChunk(prequest);
        StyledDocument doc = requestdoc;
        tcompo.setStyledDocument(doc);
    }

    /**
     * Set Response data through Chunks for binary large data
     *
     * @param presponse
     */
    public void setResponseChunks(PResponse presponse) {
        if (tcompo == null) return;
        StyledDocument blank = new DefaultStyledDocument();

        // if you change or newly create Document in JEditorPane's Document, JEditorPane cannot
        // display contents. this problem occur only ZAP.
        // Thus you must get original Document from JEditorPane for Setting Text.
        tcompo.setStyledDocument(blank);

        StyledDocumentWithChunk responsedoc = new StyledDocumentWithChunk(presponse);
        StyledDocument doc = responsedoc;

        tcompo.setStyledDocument(doc);
    }
}
