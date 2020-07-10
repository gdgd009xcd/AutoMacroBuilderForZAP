/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder;

import java.awt.Color;
import java.awt.Font;
import java.awt.Insets;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.border.LineBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;

@SuppressWarnings({"unchecked", "serial"})
public class StyledDocumentWithChunk extends DefaultStyledDocument {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private Style CRstyle = null;

    public static final String RESOURCES =
            "/org/zaproxy/zap/extension/automacrobuilder/zap/resources";

    public static final URL BINICONURL =
            ParmGenTextDoc.class.getResource(RESOURCES + "/binary.png");

    public static final URL BRKICONURL =
            ParmGenTextDoc.class.getResource(RESOURCES + "/broken.png");

    public static String CONTENTS_PLACEHOLDER_PREFIX = "<__X_PARMGEN:";
    public static String CONTENTS_PLACEHOLDER_SUFFIX = ":NEGMRAP_X__>";

    Encode enc = null;
    String host;
    int port;
    boolean isSSL;
    List<PRequest.RequestChunk> requestChunks = null;
    List<PResponse.ResponseChunk> responseChunks = null;

    public StyledDocumentWithChunk(PRequest prequest) {
        super();
        enc = prequest.getPageEnc();
        host = prequest.getHost();
        port = prequest.getPort();
        isSSL = prequest.isSSL();
        updateRequest(prequest);
    }

    public StyledDocumentWithChunk(PResponse presponse) {
        super();
        enc = presponse.getPageEnc();
        updateResponse(presponse);
    }

    /**
     * this document for Prequest or not.
     *
     * @return
     */
    public boolean isRequest() {
        return requestChunks != null ? true : false;
    }

    public List<PRequest.RequestChunk> getRequestChunks() {
        return requestChunks;
    }

    List<PResponse.ResponseChunk> getResponseChunks() {
        return responseChunks;
    }

    /**
     * Rebuild Chunk PRequest from intenal text
     *
     * @param text
     * @return
     */
    public PRequest reBuildChunkPRequestFromDocText() {
        return reBuildChunkPRequestFromDocText(null);
    }

    /**
     * Rebuild Chunk PRequest from specified(or intenal) text
     *
     * @param text
     * @return
     */
    private PRequest reBuildChunkPRequestFromDocText(String text) {
        if (requestChunks == null) return null;
        try {
            if (text == null || text.isEmpty()) {
                text = this.getText(0, getLength());
            }
            Charset charset = enc.getIANACharset();
            byte[] docbytes = text.getBytes(charset);
            ParmGenBinUtil contarray = new ParmGenBinUtil(docbytes);
            ParmGenBinUtil resultarray = new ParmGenBinUtil();
            byte[] PLS_PREFIX = CONTENTS_PLACEHOLDER_PREFIX.getBytes();
            byte[] PLS_SUFFIX = CONTENTS_PLACEHOLDER_SUFFIX.getBytes();
            int npos = -1;
            int cpos = 0;
            int sfxstpos = -1;
            while ((npos = contarray.indexOf(PLS_PREFIX, cpos)) != -1) {
                resultarray.concat(contarray.subBytes(cpos, npos));
                cpos = npos + PLS_PREFIX.length;
                if ((sfxstpos = contarray.indexOf(PLS_SUFFIX, cpos)) != -1) {
                    if (sfxstpos > cpos && sfxstpos - cpos <= 3) {
                        String nstr = new String(contarray.subBytes(cpos, sfxstpos), charset);
                        if (nstr.matches("[0-9]+")) {
                            int partno = Integer.parseInt(nstr);
                            Optional<PRequest.RequestChunk> ochunk =
                                    requestChunks.stream()
                                            .filter(
                                                    c ->
                                                            c.getChunkType()
                                                                            == PRequest.RequestChunk
                                                                                    .CHUNKTYPE
                                                                                    .CONTENTS
                                                                    && c.getPartNo() == partno)
                                            .findFirst();
                            PRequest.RequestChunk resultchunk = ochunk.orElse(null);
                            if (resultchunk != null && resultchunk.getBytes().length > 0) {
                                resultarray.concat(resultchunk.getBytes());
                            }
                            cpos = sfxstpos + PLS_SUFFIX.length;
                        }
                    }
                }
            }
            if (cpos < docbytes.length) {
                resultarray.concat(contarray.subBytes(cpos, docbytes.length));
            }
            PRequest newrequest = new PRequest(host, port, isSSL, resultarray.getBytes(), enc);
            requestChunks = newrequest.getRequestChunks();
            return newrequest;
        } catch (BadLocationException ex) {
            Logger.getLogger(StyledDocumentWithChunk.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * update StyledDocument with specified request binary data. this method use carefully. host,
     * port, isSSL, enc parameter is No changed. so if you need to update these 4 params then you
     * must newly create this instance.
     *
     * @param reqbin
     */
    public void updateRequest(byte[] reqbin) {
        PRequest newrequest = null;

        try {
            newrequest = new PRequest(host, port, isSSL, reqbin, enc);
        } catch (Exception e) {
            return;
        }

        if (newrequest == null) return;
        updateRequest(newrequest);
    }

    /**
     * get bytes from Chunks.
     *
     * @return
     */
    public byte[] getBytes() {
        ParmGenBinUtil bb = new ParmGenBinUtil();
        if (requestChunks != null) {
            requestChunks.forEach(
                    chunk -> {
                        bb.concat(chunk.getBytes());
                    });
        } else if (responseChunks != null) {
            responseChunks.forEach(
                    chunk -> {
                        bb.concat(chunk.getBytes());
                    });
        }
        return bb.getBytes();
    }

    /**
     * update styleedoc by request bytes. large binary data representation is image icon.
     *
     * @param prequest
     */
    private void updateRequest(PRequest newrequest) {

        requestChunks = newrequest.getRequestChunks();
        responseChunks = null;

        // update StyledDocument with requestChunk
        updateRequest();
    }

    public void updateRequestFromText(String text) {

        if (requestChunks == null) return;

        // update requestChunk with text.
        reBuildChunkPRequestFromDocText(text);

        // update StyledDocument with requestChunk
        updateRequest();
    }

    /** update StyledDocument with requestChunk */
    private void updateRequest() {
        Encode pageenc = this.enc;

        responseChunks = null;

        try {
            this.remove(0, this.getLength());
        } catch (BadLocationException ex) {
            Logger.getLogger(StyledDocumentWithChunk.class.getName()).log(Level.SEVERE, null, ex);
        }

        // if you change or newly create Document in JEditorPane's Document, JEditorPane cannot
        // display contents. this problem occur only ZAP.
        // Thus you must get original Document from JEditorPane for Setting Text.

        Style def = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);

        List<PRequest.RequestChunk> chunks = requestChunks;

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
                                                .replaceAll("\r", "<CR>")
                                        + "]");
                        // insertString(pos, element, null);
                        insertStringCR(pos, element);
                        // pos = pos + element.length();
                        break;
                    case BOUNDARY:
                        LOGGER4J.debug(
                                "@BOUNDARY["
                                        + new String(chunk.getBytes(), pageenc.getIANACharset())
                                        + "]");
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        // insertString(pos, element, null);
                        insertStringCR(pos, element);
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
                        // insertString(pos, element, null);
                        insertStringCR(pos, element);
                        break;
                    case CONTENTS:
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        Style s = null;
                        if (chunk.getBytes().length > 20000) {
                            // s = doc.getStyle("binary");
                            String partno =
                                    CONTENTS_PLACEHOLDER_PREFIX
                                            + chunk.getPartNo()
                                            + CONTENTS_PLACEHOLDER_SUFFIX;
                            ImageIcon icon = null;
                            if (displayableimgtype.isEmpty()) {
                                icon = new ImageIcon(BINICONURL, partno);
                            } else {
                                try {
                                    icon = new ImageIcon(chunk.getBytes(), partno);
                                } catch (Exception e) {
                                    icon = new ImageIcon(BRKICONURL, partno);
                                }
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

                        if (s == null) {
                            insertStringCR(pos, element);
                        } else {
                            insertString(pos, element, s);
                        }
                        break;
                    case CONTENTSEND:
                        LOGGER4J.debug(
                                "@CONTENTSSEND["
                                        + new String(chunk.getBytes(), pageenc.getIANACharset())
                                        + "]");
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        // insertString(pos, element, null);
                        insertStringCR(pos, element);
                        break;
                    case LASTBOUNDARY:
                        LOGGER4J.debug(
                                "@LASTBOUNDARY["
                                        + new String(chunk.getBytes(), pageenc.getIANACharset())
                                        + "]");
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        // insertString(pos, element, null);
                        insertStringCR(pos, element);
                        break;
                }
                pos = this.getLength();
            }
        } catch (BadLocationException ex) {
            Logger.getLogger(ParmGenTextDoc.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Set request contents into styleedoc. large binary data representation is image icon.
     *
     * @param presponse
     */
    public void updateResponse(PResponse presponse) {

        // if you change or newly create Document in JEditorPane's Document, JEditorPane cannot
        // display contents. this problem occur only ZAP.
        // Thus you must get original Document from JEditorPane for Setting Text.

        enc = presponse.getPageEnc();
        responseChunks = presponse.getResponseChunks();
        requestChunks = null;

        try {
            this.remove(0, this.getLength());
        } catch (BadLocationException ex) {
            Logger.getLogger(StyledDocumentWithChunk.class.getName()).log(Level.SEVERE, null, ex);
        }

        Style def = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);

        String partno = CONTENTS_PLACEHOLDER_PREFIX + "0" + CONTENTS_PLACEHOLDER_SUFFIX;
        StyleConstants.setAlignment(def, StyleConstants.ALIGN_CENTER);

        List<PResponse.ResponseChunk> chunks = responseChunks;

        Charset charset = presponse.getPageEnc().getIANACharset();

        int pos = 0;

        try {
            for (PResponse.ResponseChunk chunk : chunks) {
                Style s = null;
                String elem;
                ImageIcon icon = null;
                switch (chunk.getChunkType()) {
                    case CONTENTSBINARY:
                        icon = new ImageIcon(BINICONURL, partno);
                        s = makeStyleImageButton(def, icon, partno);
                        elem = partno;
                        LOGGER4J.debug("CONTENTSBINARY[" + elem + "]pos:" + pos);
                        break;
                    case CONTENTSIMG:
                        try {
                            icon = new ImageIcon(chunk.getBytes(), partno);
                        } catch (Exception e) {
                            icon = new ImageIcon(BRKICONURL, partno);
                        }
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
                insertString(pos, elem, s);
                pos = getLength();
            }
        } catch (Exception e) {

        }
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

    Style getCRstyle() {

        Style defstyle = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);
        // StyleConstants.setAlignment(defstyle, StyleConstants.ALIGN_CENTER);
        JLabel crlabel = new JLabel("CR");
        crlabel.setOpaque(true);
        LineBorder border = new LineBorder(Color.GREEN, 1, true);
        Font labelFont = crlabel.getFont();
        crlabel.setFont(new Font(labelFont.getName(), Font.PLAIN, 8));
        crlabel.setBorder(border);
        float avf = crlabel.getAlignmentY();
        // LOGGER4J.debug("Y=" + avf);
        avf = (float) 0.8;
        crlabel.setAlignmentY(avf);
        CRstyle = defstyle;
        StyleConstants.setComponent(CRstyle, crlabel);
        return CRstyle;
    }

    /**
     * insert String with CR displayed
     *
     * @param pos
     * @param text
     */
    private void insertStringCR(int pos, String text) {
        if (text == null || text.length() < 1) return;
        int cpos = 0;
        int npos = -1;
        int totallen = text.length();
        while ((npos = text.indexOf("\r", cpos)) != -1) {
            try {
                this.insertString(pos, text.substring(cpos, npos), null);
                cpos = npos;
                pos = this.getLength();
                this.insertString(pos, text.substring(cpos, cpos + 1), getCRstyle());
                cpos++;
                pos = this.getLength();
            } catch (BadLocationException ex) {
                Logger.getLogger(StyledDocumentWithChunk.class.getName())
                        .log(Level.SEVERE, null, ex);
            }
        }
        if (cpos < totallen) {
            try {
                this.insertString(pos, text.substring(cpos, totallen), null);
            } catch (BadLocationException ex) {
                Logger.getLogger(StyledDocumentWithChunk.class.getName())
                        .log(Level.SEVERE, null, ex);
            }
        }
    }
}
