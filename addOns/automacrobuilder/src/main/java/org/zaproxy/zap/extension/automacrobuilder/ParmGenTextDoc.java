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
package org.zaproxy.zap.extension.automacrobuilder;

import java.awt.Insets;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Document;
import javax.swing.text.JTextComponent;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;
import javax.swing.text.StyledDocument;
import org.zaproxy.zap.extension.automacrobuilder.PResponse.ResponseChunk;

/** @author youtube */
public class ParmGenTextDoc {
    private static final String RESOURCES =
            "/org/zaproxy/zap/extension/automacrobuilder/zap/resources";

    private static final URL IMGICONURL =
            ParmGenTextDoc.class.getResource(RESOURCES + "/binary.png");

    private JTextPane tcompo;
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public ParmGenTextDoc(JTextPane tc) {
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
                Logger.getLogger(ParmGenTextDoc.class.getName()).log(Level.SEVERE, null, ex);
            }

            try {
                LOGGER4J.debug("before  insert text size=" + text.length());
                doc.insertString(0, text, null);
                LOGGER4J.debug("insert  done");
            } catch (BadLocationException ex) {
                Logger.getLogger(ParmGenTextDoc.class.getName()).log(Level.SEVERE, null, ex);
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
        StyledDocument doc = null;
        if (tcompo == null) return;
        StyledDocument blank = new DefaultStyledDocument();

        // if you change or newly create Document in JEditorPane's Document, JEditorPane cannot
        // display contents. this problem occur only ZAP.
        // Thus you must get original Document from JEditorPane for Setting Text.
        doc = tcompo.getStyledDocument();
        tcompo.setStyledDocument(blank);

        try {
            LOGGER4J.debug("before  remove text");
            doc.remove(0, doc.getLength());
            LOGGER4J.debug("done remove text");
        } catch (BadLocationException ex) {
            Logger.getLogger(ParmGenTextDoc.class.getName()).log(Level.SEVERE, null, ex);
        }

        doc = new DefaultStyledDocument();

        Style def = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);

        List<PRequest.RequestChunk> chunks = prequest.getRequestChunks();
        Encode pageenc = prequest.getPageEnc();
        int pos = 0;
        String displayableimgtype = "";
        try {
            for (PRequest.RequestChunk chunk : chunks) {
                String element = "";
                switch (chunk.getChunkType()) {
                    case REQUESTHEADER:
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        LOGGER4J.debug(
                                "@REQUESTHEADER["
                                        + new String(chunk.getBytes(), pageenc.getIANACharset())
                                        + "]");
                        doc.insertString(pos, element, null);
                        pos = pos + element.length();
                        break;
                    case BOUNDARY:
                        LOGGER4J.debug(
                                "@BOUNDARY["
                                        + new String(chunk.getBytes(), pageenc.getIANACharset())
                                        + "]");
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        doc.insertString(pos, element, null);
                        pos = pos + element.length();
                        break;
                    case BOUNDARYHEADER:
                        LOGGER4J.debug(
                                "@BOUNDARYHEADER["
                                        + new String(chunk.getBytes(), pageenc.getIANACharset())
                                        + "]");
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        displayableimgtype = "";
                        List<String> matches =
                                ParmGenUtil.getRegexMatchGroups(
                                        "Content-Type: image/(jpeg|png|gif)", element);
                        matches.forEach(s -> LOGGER4J.debug(s));
                        if (!matches.isEmpty()) {
                            displayableimgtype = matches.get(0);
                        }
                        doc.insertString(pos, element, null);
                        pos = pos + element.length();
                        break;
                    case CONTENTS:
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        Style s = null;
                        if (chunk.getBytes().length > 20000) {
                            // s = doc.getStyle("binary");
                            String partno = "X-PARMGEN:" + chunk.getPartNo();
                            ImageIcon icon = null;
                            if (displayableimgtype.isEmpty()) {
                                icon = new ImageIcon(IMGICONURL, partno);
                            } else {
                                icon = new ImageIcon(chunk.getBytes(), partno);
                            }
                            // doc.addStyle(partno, def);
                            s = makeStyleImageButton(def, icon, partno);
                            LOGGER4J.debug("@CONTENTS length:" + chunk.getBytes().length);
                            element = partno;
                        } else {
                            s = null;
                            LOGGER4J.debug(
                                    "@CONTENTS["
                                            + new String(chunk.getBytes(), pageenc.getIANACharset())
                                            + "]");
                        }

                        doc.insertString(pos, element, s);
                        pos = pos + element.length();
                        break;
                    case CONTENTSEND:
                        LOGGER4J.debug(
                                "@CONTENTSSEND["
                                        + new String(chunk.getBytes(), pageenc.getIANACharset())
                                        + "]");
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        doc.insertString(pos, element, null);
                        pos = pos + element.length();
                        break;
                    case LASTBOUNDARY:
                        LOGGER4J.debug(
                                "@LASTBOUNDARY["
                                        + new String(chunk.getBytes(), pageenc.getIANACharset())
                                        + "]");
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        doc.insertString(pos, element, null);
                        pos = pos + element.length();
                        break;
                }
            }
        } catch (BadLocationException ex) {
            Logger.getLogger(ParmGenTextDoc.class.getName()).log(Level.SEVERE, null, ex);
        }
        tcompo.setStyledDocument(doc);
    }

    /**
     * Set Response data through Chunks for binary large data
     *
     * @param presponse
     */
    public void setResponseChunks(PResponse presponse) {
        LOGGER4J.debug("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! setResponseChunks");
        StyledDocument doc = null;
        if (tcompo == null) return;
        StyledDocument blank = new DefaultStyledDocument();

        // if you change or newly create Document in JEditorPane's Document, JEditorPane cannot
        // display contents. this problem occur only ZAP.
        // Thus you must get original Document from JEditorPane for Setting Text.
        doc = tcompo.getStyledDocument();
        tcompo.setStyledDocument(blank);

        try {
            LOGGER4J.debug("before  remove text");
            doc.remove(0, doc.getLength());
            LOGGER4J.debug("done remove text");
        } catch (BadLocationException ex) {
            Logger.getLogger(ParmGenTextDoc.class.getName()).log(Level.SEVERE, null, ex);
        }

        doc = new DefaultStyledDocument();

        Style def = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);

        String partno = "X-PARMGEN:0";
        StyleConstants.setAlignment(def, StyleConstants.ALIGN_CENTER);

        List<PResponse.ResponseChunk> chunks = presponse.getResponseChunks();
        Charset charset = presponse.getPageEnc().getIANACharset();

        int pos = 0;

        try {
            for (ResponseChunk chunk : chunks) {
                Style s = null;
                String elem;
                ImageIcon icon = null;
                switch (chunk.getChunkType()) {
                    case CONTENTSBINARY:
                        icon = new ImageIcon(IMGICONURL, partno);
                        s = makeStyleImageButton(def, icon, partno);
                        elem = partno;
                        LOGGER4J.debug("CONTENTSBINARY[" + elem + "]pos:" + pos);
                        break;
                    case CONTENTSIMG:
                        icon = new ImageIcon(chunk.getBytes(), partno);
                        s = makeStyleImageButton(def, icon, partno);
                        elem = partno;
                        LOGGER4J.debug("CONTENTSIMG[" + elem + "]pos:" + pos);
                        break;
                    case RESPONSEHEADER:
                        elem = new String(chunk.getBytes(), charset);
                        LOGGER4J.debug("RESPONSEHEADER[" + elem + "]pos:" + pos);
                        break;
                    default: // CONTENTS
                        elem = new String(chunk.getBytes(), charset);
                        LOGGER4J.debug("CONTENTS[" + elem + "]pos:" + pos);
                        break;
                }
                doc.insertString(pos, elem, s);
                pos += elem.length();
            }
        } catch (Exception e) {

        }
        tcompo.setStyledDocument(doc);
    }

    /**
     * create button with ImageIcon and add eventhandler.
     *
     * @param s
     * @param icon
     * @param actioncommand
     * @return
     */
    public Style makeStyleImageButton(Style s, ImageIcon icon, String actioncommand) {
        StyleConstants.setAlignment(s, StyleConstants.ALIGN_CENTER);
        JButton button = new JButton();
        button.setIcon(icon);
        button.setMargin(new Insets(0, 0, 0, 0));
        button.setActionCommand(actioncommand);
        button.addActionListener(
                e -> {
                    LOGGER4J.debug("button pressed:" + e.getActionCommand());
                });
        StyleConstants.setComponent(s, button);
        return s;
    }
}
