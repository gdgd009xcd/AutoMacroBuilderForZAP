/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.view;

import org.zaproxy.zap.extension.automacrobuilder.*;

import static org.zaproxy.zap.extension.automacrobuilder.ParmGenUtil.ImageIconLoadStatus;

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

@SuppressWarnings({"unchecked", "serial"})
public class StyledDocumentWithChunk extends DefaultStyledDocument {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final String CRSTYLE_NAME = "CRSTYLE_IMAGE";

    public static int PARTNO_MAXLEN = 4;

    public static final String RESOURCES =
            "/org/zaproxy/zap/extension/automacrobuilder/zap/resources";

    public static final URL BINICONURL =
            JTextPaneContents.class.getResource(RESOURCES + "/binary.png");

    public static final URL BRKICONURL =
            JTextPaneContents.class.getResource(RESOURCES + "/broken.png");

    public static final int MAX_SIZE_REQUEST_PART = 25000;

    public static String CONTENTS_PLACEHOLDER_PREFIX = "<__X_PARMGEN:";
    public static String CONTENTS_PLACEHOLDER_SUFFIX = ":NEGMRAP_X__>";

    Encode enc = null;
    String host;
    int port;
    boolean isSSL;
    List<RequestChunk> requestChunks = null;
    List<PResponse.ResponseChunk> responseChunks = null;

    public StyledDocumentWithChunk(PRequest prequest) {
        super(SwingStyleProvider.createSwingStyle().getStyleContext());
        enc = prequest.getPageEnc();
        host = prequest.getHost();
        port = prequest.getPort();
        isSSL = prequest.isSSL();
        updateRequest(prequest);
    }

    public StyledDocumentWithChunk(PResponse presponse) {
        super(SwingStyleProvider.createSwingStyle().getStyleContext());
        enc = presponse.getPageEnc();
        updateResponse(presponse);
    }

    /**
     * create instance from specified chunkdoc this.requestChunks are deepcopied from
     * chunkdoc.requestChunks. thus this instance is independent from specified chunkdoc.
     *
     * @param chunkdoc
     */
    public StyledDocumentWithChunk(StyledDocumentWithChunk chunkdoc) {
        super(SwingStyleProvider.createSwingStyle().getStyleContext());
        if (chunkdoc != null) {
            if (chunkdoc.isRequest()) {
                LOGGER4J.debug("chunkdoc is REQUEST");
                enc = chunkdoc.enc;
                host = chunkdoc.host;
                port = chunkdoc.port;
                isSSL = chunkdoc.isSSL;
                requestChunks =
                        ListDeepCopy.listDeepCopyRequestChunk(
                                chunkdoc.requestChunks); // copy from source
                try {
                    generateStyledDocFromRequestText(chunkdoc.getText(0, chunkdoc.getLength()));
                } catch (BadLocationException ex) {
                    Logger.getLogger(StyledDocumentWithChunk.class.getName())
                            .log(Level.SEVERE, null, ex);
                }
            } else {
                LOGGER4J.debug("chunkdoc is RESPONSE");
                enc = chunkdoc.enc;
                byte[] resbin = chunkdoc.getBytes();
                PResponse response = new PResponse(resbin, enc);
                updateResponse(response);
            }
        }
    }
    /**
     * this document for Prequest or not.
     *
     * @return
     */
    public boolean isRequest() {
        return requestChunks != null ? true : false;
    }

    public List<RequestChunk> getRequestChunks() {
        return requestChunks;
    }

    List<PResponse.ResponseChunk> getResponseChunks() {
        return responseChunks;
    }

    /**
     * Rebuild PRequest from intenal text and chunks. This method no affects contents of this.
     *
     * @return
     */
    public PRequest reBuildPRequestFromDocTextAndChunks() {
        byte[] data = reBuildPRequestFromDocTextAndChunks(null);
        if (data != null) {
            return new PRequest(host, port, isSSL, data, enc, this);
        }
        return null;
    }

    /**
     * Rebuild PRequest from specified(or intenal) text This method no affects contents of this.
     *
     * @param text
     * @return
     */
    private byte[] reBuildPRequestFromDocTextAndChunks(String text) {
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
                    if (sfxstpos > cpos && sfxstpos - cpos <= PARTNO_MAXLEN) {
                        String nstr = new String(contarray.subBytes(cpos, sfxstpos), charset);
                        if (nstr.matches("[0-9]+")) {
                            int partno = Integer.parseInt(nstr);
                            Optional<RequestChunk> ochunk =
                                    requestChunks.stream()
                                            .filter(
                                                    c ->
                                                            (c.getChunkType()
                                                                                    == RequestChunk
                                                                                            .CHUNKTYPE
                                                                                            .CONTENTS
                                                                            || c.getChunkType()
                                                                                    == RequestChunk
                                                                                            .CHUNKTYPE
                                                                                            .CONTENTSIMG)
                                                                    && c.getPartNo() == partno)
                                            .findFirst();
                            RequestChunk resultchunk = ochunk.orElse(null);
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

            // requestChunks = newrequest.getRequestChunks();
            return resultarray.getBytes();
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
     * @param hexbytes
     */
    public void updateStyleDocAndChunkFromHex(byte[] hexbytes) {
        if (hexbytes == null) return;
        Charset charset = enc.getIANACharset();
        String doctext = "";

        try {
            doctext = this.getText(0, this.getLength());
        } catch (BadLocationException ex) {
            Logger.getLogger(StyledDocumentWithChunk.class.getName()).log(Level.SEVERE, null, ex);
            return;
        }

        byte[] docbytes = doctext.getBytes(charset);
        ParmGenBinUtil docarray = new ParmGenBinUtil(docbytes);
        ParmGenBinUtil hexarray = new ParmGenBinUtil(hexbytes);
        ParmGenBinUtil resultarray = new ParmGenBinUtil();
        byte[] PLS_PREFIX = CONTENTS_PLACEHOLDER_PREFIX.getBytes();
        byte[] PLS_SUFFIX = CONTENTS_PLACEHOLDER_SUFFIX.getBytes();
        int npos = -1;
        int cpos = 0;
        int hpos = 0;
        while ((npos = docarray.indexOf(PLS_PREFIX, cpos)) != -1) {
            int siz = 0;
            if (npos > cpos) {
                siz = npos - cpos;
                resultarray.concat(hexarray.subBytes(hpos, hpos + siz));
                hpos += siz;
            }
            cpos = npos + PLS_PREFIX.length;
            resultarray.concat(PLS_PREFIX);

            if ((npos = docarray.indexOf(PLS_SUFFIX, cpos)) != -1) {
                if (npos > cpos && npos - cpos <= PARTNO_MAXLEN) {
                    byte[] partnobytes = docarray.subBytes(cpos, npos);
                    String partnostr = new String(partnobytes, charset);
                    if (partnostr.matches("[0-9]+")) {
                        int partno = Integer.parseInt(partnostr);
                        Optional<RequestChunk> ochunk =
                                requestChunks.stream()
                                        .filter(
                                                c ->
                                                        (c.getChunkType()
                                                                                == RequestChunk
                                                                                        .CHUNKTYPE
                                                                                        .CONTENTS
                                                                        || c.getChunkType()
                                                                                == RequestChunk
                                                                                        .CHUNKTYPE
                                                                                        .CONTENTSIMG)
                                                                && c.getPartNo() == partno)
                                        .findFirst();
                        RequestChunk resultchunk = ochunk.orElse(null);
                        if (resultchunk != null) {
                            siz = resultchunk.getBytes().length;
                            if (siz > 0) {
                                // update resultChunk.data with hexdata.
                                resultchunk.setByte(hexarray.subBytes(hpos, hpos + siz));
                                LOGGER4J.debug(
                                        "update chunk from hexdata partno:"
                                                + partno
                                                + " siz="
                                                + siz);
                                hpos += siz;
                            }
                        }
                    }
                }
                npos += PLS_SUFFIX.length;
                resultarray.concat(docarray.subBytes(cpos, npos));
                cpos = npos;
            }
        }
        if (hpos < hexbytes.length) {
            resultarray.concat(hexarray.subBytes(hpos, hexbytes.length));
        }
        generateStyledDocFromRequestText(new String(resultarray.getBytes(), charset));
    }

    /**
     * get bytes from Chunks.
     *
     * @return
     */
    public byte[] getBytes() {
        if (requestChunks != null) {
            byte[] reqbin = reBuildPRequestFromDocTextAndChunks(null);
            if (reqbin != null) {
                return reqbin;
            }
        } else if (responseChunks != null) {
            ParmGenBinUtil bb = new ParmGenBinUtil();
            responseChunks.forEach(
                    chunk -> {
                        bb.concat(chunk.getBytes());
                    });
            return bb.getBytes();
        }
        return null;
    }

    /**
     * update styleedoc by request bytes. large binary data representation is image icon.
     *
     * @param newrequest
     */
    private void updateRequest(PRequest newrequest) {

        requestChunks = newrequest.getRequestChunks();
        responseChunks = null;

        String text = newrequest.getDocText();

        if (text != null && text.length() > 0) {
            // update StyledDocument with text
            generateStyledDocFromRequestText(text);
        } else {
            // update StyledDocument with requestChunk
            updateRequest();
            newrequest.setDocText(this);
        }
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

        Style defaultStyle = SwingStyle.getDefaultStyle(this);

        List<RequestChunk> chunks = requestChunks;

        int pos = 0;
        String displayableimgtype = "";
        try {
            for (RequestChunk chunk : chunks) {
                String element = "";
                switch (chunk.getChunkType()) {
                    case REQUESTHEADER:
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        LOGGER4J.trace(
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
                        // insertString(pos, element, null);
                        insertStringCR(pos, element);
                        break;
                    case CONTENTSIMG:
                        {
                            Style s = null;
                            if (chunk.getBytes().length > MAX_SIZE_REQUEST_PART) {
                                // s = doc.getStyle("binary");
                                String partno =
                                        CONTENTS_PLACEHOLDER_PREFIX
                                                + chunk.getPartNo()
                                                + CONTENTS_PLACEHOLDER_SUFFIX;
                                ImageIcon icon = null;

                                try {
                                    icon = new ImageIcon(chunk.getBytes(), partno);
                                    LOGGER4J.debug("icon status:" + ImageIconLoadStatus(icon));
                                } catch (Exception e) {
                                    icon = new ImageIcon(BRKICONURL, partno);
                                }
                                // doc.addStyle(partno, def);
                                s = makeStyleImageButton(defaultStyle, icon, partno);
                                LOGGER4J.debug("@CONTENTS length:" + chunk.getBytes().length);
                                element = partno;
                            } else {
                                s = null;
                                LOGGER4J.trace(
                                        "@CONTENTS["
                                                + new String(
                                                        chunk.getBytes(), pageenc.getIANACharset())
                                                + "]");
                                element = new String(chunk.getBytes(), pageenc.getIANACharset());
                            }

                            if (s == null) {
                                insertStringCR(pos, element);
                            } else {
                                insertString(pos, element, s);
                            }
                        }
                        break;
                    case CONTENTS:
                        Style s = null;
                        if (chunk.getBytes().length > MAX_SIZE_REQUEST_PART) {
                            // s = doc.getStyle("binary");
                            String partno =
                                    CONTENTS_PLACEHOLDER_PREFIX
                                            + chunk.getPartNo()
                                            + CONTENTS_PLACEHOLDER_SUFFIX;
                            ImageIcon icon = new ImageIcon(BINICONURL, partno);
                            // doc.addStyle(partno, def);
                            s = makeStyleImageButton(defaultStyle, icon, partno);
                            LOGGER4J.debug("BINICONED @CONTENTS length:" + chunk.getBytes().length);
                            element = partno;
                        } else {
                            s = null;
                            LOGGER4J.trace(
                                    "@CONTENTS["
                                            + new String(chunk.getBytes(), pageenc.getIANACharset())
                                            + "]");
                            element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        }

                        if (s == null) {
                            insertStringCR(pos, element);
                        } else {
                            insertString(pos, element, s);
                        }
                        break;
                    case CONTENTSEND:
                        LOGGER4J.trace(
                                "@CONTENTSSEND["
                                        + new String(chunk.getBytes(), pageenc.getIANACharset())
                                        + "]");
                        element = new String(chunk.getBytes(), pageenc.getIANACharset());
                        // insertString(pos, element, null);
                        insertStringCR(pos, element);
                        break;
                    case LASTBOUNDARY:
                        LOGGER4J.trace(
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
            Logger.getLogger(JTextPaneContents.class.getName()).log(Level.SEVERE, null, ex);
        }
        LOGGER4J.debug("doc.length:" + this.getLength());
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

        Style defaultStyle = SwingStyle.getDefaultStyle(this);

        String partno = CONTENTS_PLACEHOLDER_PREFIX + "0" + CONTENTS_PLACEHOLDER_SUFFIX;
        StyleConstants.setAlignment(defaultStyle, StyleConstants.ALIGN_CENTER);

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
                        s = makeStyleImageButton(defaultStyle, icon, partno);
                        elem = partno;
                        LOGGER4J.debug("CONTENTSBINARY[" + elem + "]pos:" + pos);
                        break;
                    case CONTENTSIMG:
                        try {
                            icon = new ImageIcon(chunk.getBytes(), partno);
                            LOGGER4J.debug("icon status:" + ImageIconLoadStatus(icon));
                        } catch (Exception e) {
                            icon = new ImageIcon(BRKICONURL, partno);
                        }
                        s = makeStyleImageButton(defaultStyle, icon, partno);
                        elem = partno;
                        LOGGER4J.debug("CONTENTSIMG[" + elem + "]pos:" + pos);
                        break;
                    case RESPONSEHEADER:
                        elem = new String(chunk.getBytes(), charset);
                        LOGGER4J.debug("RESPONSEHEADER[" + elem + "]pos:" + pos);
                        break;
                    default: // CONTENTS
                        elem = new String(chunk.getBytes(), charset);
                        LOGGER4J.trace("CONTENTS[" + elem + "]pos:" + pos);
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

    public Style getCRstyle() {
        Style CRstyle = this.getStyle(CRSTYLE_NAME);
        if (CRstyle == null) {
            Style defaultStyle = SwingStyle.getDefaultStyle(this);
            CRstyle = this.addStyle(CRSTYLE_NAME, defaultStyle);
        }

        // component must always create per call setComponent.
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
        // StyleConstants.setAlignment(defstyle, StyleConstants.ALIGN_CENTER);
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

    /**
     * Generate StyledDocument from RequestText
     *
     * @param requesttext
     */
    private void generateStyledDocFromRequestText(String requesttext) {

        if (requesttext == null || requesttext.isEmpty() || requestChunks == null) return;

        try {
            this.remove(0, this.getLength());
        } catch (BadLocationException ex) {
            Logger.getLogger(StyledDocumentWithChunk.class.getName()).log(Level.SEVERE, null, ex);
        }

        int npos = -1;
        int cpos = 0;
        while ((npos = requesttext.indexOf(CONTENTS_PLACEHOLDER_PREFIX, cpos)) != -1) {
            LOGGER4J.debug("CONTENTS_PLACEHOLDER_PREFIX found");
            if (npos > cpos) {
                insertStringCR(this.getLength(), requesttext.substring(cpos, npos));
            }
            cpos = npos;
            String element = CONTENTS_PLACEHOLDER_PREFIX;
            Style s = null;
            int pnopos = cpos + CONTENTS_PLACEHOLDER_PREFIX.length(); // partno start position
            if ((npos = requesttext.indexOf(CONTENTS_PLACEHOLDER_SUFFIX, pnopos)) != -1) {
                LOGGER4J.debug(
                        "CONTENTS_PLACEHOLDER_SUFFIX found npos,cpos="
                                + npos
                                + ","
                                + pnopos
                                + " ["
                                + requesttext.substring(pnopos, npos)
                                + "]");
                if (npos > pnopos && npos - pnopos <= PARTNO_MAXLEN) {
                    element =
                            CONTENTS_PLACEHOLDER_PREFIX
                                    + requesttext.substring(pnopos, npos)
                                    + CONTENTS_PLACEHOLDER_SUFFIX;
                    LOGGER4J.debug("element[" + element + "]");
                    String nstr = requesttext.substring(pnopos, npos).trim();
                    if (nstr.matches("[0-9]+")) {
                        int partno = Integer.parseInt(nstr);
                        String partnostr = Integer.toString(partno);
                        Optional<RequestChunk> ochunks =
                                requestChunks.stream()
                                        .filter(
                                                c ->
                                                        (c.getChunkType()
                                                                                == RequestChunk
                                                                                        .CHUNKTYPE
                                                                                        .CONTENTS
                                                                        || c.getChunkType()
                                                                                == RequestChunk
                                                                                        .CHUNKTYPE
                                                                                        .CONTENTSIMG)
                                                                && c.getPartNo() == partno)
                                        .findFirst();
                        RequestChunk content_chunk = ochunks.orElse(null);
                        if (content_chunk != null && content_chunk.getBytes().length > 0) {
                            ImageIcon icon = null;
                            if (content_chunk.getChunkType() == RequestChunk.CHUNKTYPE.CONTENTS) {
                                icon = new ImageIcon(BINICONURL, partnostr);
                            } else { // diplayable image
                                try {
                                    icon = new ImageIcon(content_chunk.getBytes(), partnostr);
                                    LOGGER4J.debug("icon status:" + ImageIconLoadStatus(icon));
                                } catch (Exception e) {
                                    icon = new ImageIcon(BRKICONURL, partnostr);
                                }
                            }
                            Style defstyle = SwingStyle.getDefaultStyle(this);
                            s = makeStyleImageButton(defstyle, icon, partnostr);
                        }
                    }
                }
            }
            if (s != null) {
                try {
                    this.insertString(this.getLength(), element, s);
                } catch (BadLocationException ex) {
                    Logger.getLogger(StyledDocumentWithChunk.class.getName())
                            .log(Level.SEVERE, null, ex);
                }
            } else {
                insertStringCR(this.getLength(), element);
            }
            cpos += element.length();
        }
        if (cpos < requesttext.length()) {
            insertStringCR(this.getLength(), requesttext.substring(cpos, requesttext.length()));
        }
    }
}
