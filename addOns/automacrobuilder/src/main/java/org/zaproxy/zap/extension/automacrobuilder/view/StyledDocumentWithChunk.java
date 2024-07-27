/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.view;

import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.zap.CustomTagConverter;
import org.zaproxy.zap.extension.automacrobuilder.zap.DecoderTag;
import org.zaproxy.zap.extension.automacrobuilder.zap.ZapUtil;
import org.zaproxy.zap.extension.automacrobuilder.zap.view.MessageRequestDocumentFilter;

import static org.zaproxy.zap.extension.automacrobuilder.ParmGenUtil.ImageIconLoadStatus;

import java.awt.*;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.border.LineBorder;
import javax.swing.text.*;

@SuppressWarnings({"unchecked", "serial"})
public class StyledDocumentWithChunk extends ManagedStyledDocument {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final String EMBED_ISO8859_BINARY = "EMBED_ISO8859_BINARY";
    private static final String CRIMAGE_STYLENAME_PREFIX = "CARIDGE_RETURN";

    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    private static final String PLACE_HOLDER_SIGN = "§";
    private final String[] styleNames = {
            EMBED_ISO8859_BINARY
    };

    Map<String, Style> styleMap = null;

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

    int counterCaridgeReturn = 0;

    private boolean documentFilterMasked =false;

    /**
     * null constructor
     */
    public StyledDocumentWithChunk() {
        super(SwingStyleProvider.createSwingStyle().getStyleContext());
        createStyles();
    }

    /**
     * convert Prequest to StyledDocumentWithChunk
     *
     * @param prequest
     * @param decodeCustomTag true - decode CustomTag | false - no effect
     */
    public StyledDocumentWithChunk(PRequest prequest, boolean decodeCustomTag) {
        super(SwingStyleProvider.createSwingStyle().getStyleContext());
        createStyles();
        enc = prequest.getPageEnc();
        host = prequest.getHost();
        port = prequest.getPort();
        isSSL = prequest.isSSL();
        updateRequest(prequest);

        if (decodeCustomTag) {
            String placeHolderStyledText;

            placeHolderStyledText = getDecodedPlaceHolderStyledText();

            reCreateStyledDocFromRequestTextAndChunks(placeHolderStyledText, null);
        }
        if(this.getDocumentFilter() == null){
            this.setDocumentFilter(new MessageRequestDocumentFilter(this));
        }
    }

    public StyledDocumentWithChunk(PResponse presponse) {
        super(SwingStyleProvider.createSwingStyle().getStyleContext());
        createStyles();
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
        createStyles();
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
                reCreateStyledDocFromRequestTextAndChunks(chunkdoc.getPlaceHolderStyledText(), null);
                if(this.getDocumentFilter() == null){
                    this.setDocumentFilter(new MessageRequestDocumentFilter(this));
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
     * update this document with specified text argument.<BR>
     * this function is effective if this document is Request.
     * @param placeHolderStyleText
     * @return
     */
    private boolean updateRequestPlaceHolderStyleText(String placeHolderStyleText) {
        if (isRequest()) {
            reCreateStyledDocFromRequestTextAndChunks(placeHolderStyleText, null);
            return true;
        }
        return false;
    }

    private void createStyles() {
        counterCaridgeReturn = 0;
        styleMap = new HashMap<>();
        for(String name: styleNames) {
            addOrGetStyle(name);
        }
    }
    private void deleteStyles() {
        for (Map.Entry<String, Style> ent : this.styleMap.entrySet()) {
            this.removeStyle(ent.getKey());
        }
    }

    /**
     * add  Style if it does not exist
     * otherwise return existing one.
     *
     * @param newStyleName
     * @return Style
     */
    private Style addOrGetStyle(String newStyleName) {
        Style style = this.getStyle(newStyleName);
        if (style == null) {
            Style defaultStyle = SwingStyle.getDefaultStyle(this);
            Style s = this.addStyle(newStyleName, defaultStyle);
            this.styleMap.put(newStyleName, s);
            return s;
        }
        return style;
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
     * return boolean value is there exist binary contents or not
     *
     * @return true - has binary contents
     *
     */
    public boolean hasBinaryContents() {
        if (isRequest()) {
            Optional<RequestChunk> reqBinChunk =
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
                                                    )
                            .findFirst();
            return reqBinChunk.isPresent();
        }
        Optional<PResponse.ResponseChunk> resBinChunk =
                responseChunks.stream()
                        .filter(c -> (c.getChunkType() == PResponse.ResponseChunk.CHUNKTYPE.CONTENTSIMG
                                || c.getChunkType() == PResponse.ResponseChunk.CHUNKTYPE.CONTENTSBINARY)).findFirst();
        return resBinChunk.isPresent();
    }

    /**
     * Rebuild PRequest from intenal text and chunks.
     * This method apply to Encode CustomTag.
     *
     * @return
     */
    public PRequest reBuildPRequestFromDocTextAndChunksWithEncodeCustomTag() {
        byte[] data = reBuildPRequestFromDocTextAndChunks(null, true);
        if (data != null) {
            return new PRequest(host, port, isSSL, data, enc);
        }
        return null;
    }

    /**
     * Rebuild PRequest from intenal text and chunks.
     * This method returns original. it does NOT apply to Encode CustomTag
     *
     * @return
     */
    private PRequest reBuildPRequestFromDocTextAndChunks(String placeHolderStyledText) {
        byte[] data = reBuildPRequestFromDocTextAndChunks(placeHolderStyledText, false);
        if (data != null) {
            return new PRequest(host, port, isSSL, data, enc);
        }
        return null;
    }

    /**
     * Rebuild PRequest binary from specified(or intenal) PlaceHolderStyleText and internal this.requestChunks.
     * This method no affects contents of this.
     *
     * @param placeHolderStyleText
     * @return binary of PRequest
     */
    /**
     * Rebuild PRequest binary from specified(or intenal) PlaceHolderStyleText and internal this.requestChunks.
     * This method apply CustomConvert if isCustomConvert == true.
     * Otherwise this method no affects contents of this.
     * @param placeHolderStyledText
     * @param isCustomConvert true - apply CustomConvert | false - no affects contents
     * @return
     */
    private byte[] reBuildPRequestFromDocTextAndChunks(String placeHolderStyledText, boolean isCustomConvert) {
        if (requestChunks == null) return null;

        if (placeHolderStyledText == null || placeHolderStyledText.isEmpty()) {
            placeHolderStyledText = this.getPlaceHolderStyledText();
        }

        if (isCustomConvert) {
            placeHolderStyledText = getEncodedPlaceHolderStyledText();
        }

        Charset charset = enc.getIANACharset();
        byte[] docbytes = placeHolderStyledText.getBytes(charset);
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
    }

    /**
     * update StyledDocument with specified hexBytes(request binary data). this method use carefully. host,
     * port, isSSL, enc parameter is No changed. so if you need to update these 4 params then you
     * must newly create this instance.
     *
     * @param hexBytes
     */
    public void updateStyleDocAndChunkFromHex(byte[] hexBytes) {
        if (hexBytes == null) return;
        this.documentFilterMasked = true;
        try {
            Charset charset = enc.getIANACharset();
            String placeHolderStyleText = this.getPlaceHolderStyledText();

            byte[] placeHolderStyleTextBytes = placeHolderStyleText.getBytes(charset);
            ParmGenBinUtil currentPLaceHolderStyleArray = new ParmGenBinUtil(placeHolderStyleTextBytes);
            ParmGenBinUtil hexArray = new ParmGenBinUtil(hexBytes);
            ParmGenBinUtil resultPlaceHolderStyleArray = new ParmGenBinUtil();// array of PlaceHolderStyleText
            byte[] PLS_PREFIX = CONTENTS_PLACEHOLDER_PREFIX.getBytes();
            byte[] PLS_SUFFIX = CONTENTS_PLACEHOLDER_SUFFIX.getBytes();
            int npos = -1;
            int cpos = 0;
            int hpos = 0;
            while ((npos = currentPLaceHolderStyleArray.indexOf(PLS_PREFIX, cpos)) != -1) {
                int siz = 0;
                if (npos > cpos) {
                    siz = npos - cpos;
                    resultPlaceHolderStyleArray.concat(hexArray.subBytes(hpos, hpos + siz));
                    hpos += siz;
                }
                cpos = npos + PLS_PREFIX.length;
                resultPlaceHolderStyleArray.concat(PLS_PREFIX);

                if ((npos = currentPLaceHolderStyleArray.indexOf(PLS_SUFFIX, cpos)) != -1) {
                    if (npos > cpos && npos - cpos <= PARTNO_MAXLEN) {
                        byte[] partnobytes = currentPLaceHolderStyleArray.subBytes(cpos, npos);
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
                                    resultchunk.setByte(hexArray.subBytes(hpos, hpos + siz));
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
                    resultPlaceHolderStyleArray.concat(currentPLaceHolderStyleArray.subBytes(cpos, npos));
                    cpos = npos;
                }
            }
            if (hpos < hexBytes.length) {
                resultPlaceHolderStyleArray.concat(hexArray.subBytes(hpos, hexBytes.length));
            }
            reCreateStyledDocFromRequestTextAndChunks(new String(resultPlaceHolderStyleArray.getBytes(), charset), null);
        } finally {
            this.documentFilterMasked = false;
        }
    }

    /**
     * get bytes from Chunks.
     *
     * @return
     */
    public byte[] getBytes() {
        if (requestChunks != null) {
            byte[] reqbin = reBuildPRequestFromDocTextAndChunks(null, false);
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
        requestChunks = newrequest.generateRequestChunks();
        responseChunks = null;
        updateRequest();
        //newrequest.setDocText(this);
    }

    private void destroyDocumentAndRecreateStyles() {
        try {
            this.remove(0, this.getLength());
            this.deleteStyles();
            this.createStyles();
        } catch (BadLocationException ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
    }
    /** update StyledDocument with requestChunk */
    private void updateRequest() {
        Encode pageenc = this.enc;

        responseChunks = null;

        destroyDocumentAndRecreateStyles();

        // if you change or newly create Document in JEditorPane's Document, JEditorPane cannot
        // display contents. this problem occur only ZAP.
        // Thus you must get original Document from JEditorPane for Setting Text.

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
                            // it's difficult to manipulate image as text in StyleDocument
                            // because the Multi-part form data has text encoding(UTF-8)
                            // but image data can't display properly with using it's encoding.
                            // so we must display image data as IMAGE ICON.
                            if (pageenc.getIANACharset() != StandardCharsets.ISO_8859_1 || chunk.getBytes().length > MAX_SIZE_REQUEST_PART) {
                                String toolTip = bundle.getString("ParmGenRegex.UndisplayableAsTextLargerData.text");
                                // s = doc.getStyle("binary");
                                String partno =
                                        CONTENTS_PLACEHOLDER_PREFIX
                                                + chunk.getPartNo()
                                                + CONTENTS_PLACEHOLDER_SUFFIX;
                                ImageIcon icon = null;

                                try {
                                    icon = new ImageIcon(chunk.getBytes(), partno);
                                    LOGGER4J.debug("icon status:" + ImageIconLoadStatus(icon));
                                } catch (Exception ex) {
                                   LOGGER4J.error(ex.getMessage(), ex);
                                }
                                if (icon.getImageLoadStatus() != MediaTracker.COMPLETE) {
                                    toolTip = bundle.getString("ParmGenRegex.BrokenData.text");
                                    icon = new ImageIcon(BRKICONURL, partno);
                                }
                                // doc.addStyle(partno, def);
                                s = makeStyleImageButton(icon, toolTip, chunk.getPartNo(), chunk.getBytes());
                                LOGGER4J.debug("@CONTENTS length:" + chunk.getBytes().length);
                                element = PLACE_HOLDER_SIGN;
                            } else {
                                LOGGER4J.trace(
                                        "@CONTENTS["
                                                + new String(
                                                        chunk.getBytes(), StandardCharsets.ISO_8859_1)
                                                + "]");
                                element = new String(chunk.getBytes(), StandardCharsets.ISO_8859_1);
                                s = this.addOrGetStyle(EMBED_ISO8859_BINARY);
                            }

                            if (s == null) {
                                insertString(pos, element, null);
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
                            s = makeStyleImageButton(icon,bundle.getString("ParmGenRegex.UndisplayableAsTextLargerData.text"),chunk.getPartNo(), chunk.getBytes());
                            LOGGER4J.debug("BINICONED @CONTENTS length:" + chunk.getBytes().length);
                            element = PLACE_HOLDER_SIGN;
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
                if (element != null && element.isEmpty()) {
                    chunk.setTextPosLen(pos, element.length());
                }
                pos = this.getLength();
            }
        } catch (BadLocationException ex) {
            LOGGER4J.error(ex.getMessage(), ex);
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

        destroyDocumentAndRecreateStyles();

        Style defaultStyle = SwingStyle.getDefaultStyle(this);

        String partno = PLACE_HOLDER_SIGN;
        StyleConstants.setAlignment(defaultStyle, StyleConstants.ALIGN_CENTER);

        List<PResponse.ResponseChunk> chunks = responseChunks;

        Charset charset = presponse.getPageEnc().getIANACharset();

        int pos = 0;

        try {
            for (PResponse.ResponseChunk chunk : chunks) {
                Style s = null;
                String elem;
                ImageIcon icon = null;
                String toolTip;
                switch (chunk.getChunkType()) {
                    case CONTENTSBINARY:
                        icon = new ImageIcon(BINICONURL, partno);
                        s = makeStyleImageButton(icon,bundle.getString("ParmGenRegex.UndisplayableAsTextLargerData.text"), 0, chunk.getBytes());
                        elem = partno;
                        LOGGER4J.debug("CONTENTSBINARY[" + elem + "]pos:" + pos);
                        break;
                    case CONTENTSIMG:
                        toolTip = bundle.getString("ParmGenRegex.UndisplayableAsTextLargerData.text");
                        try {
                            icon = new ImageIcon(chunk.getBytes(), partno);
                            LOGGER4J.debug("icon status:" + ImageIconLoadStatus(icon));
                        } catch (Exception e) {
                            icon = new ImageIcon(BRKICONURL, partno);
                        }
                        if (icon.getImageLoadStatus() != MediaTracker.COMPLETE) {
                            toolTip = bundle.getString("ParmGenRegex.BrokenData.text");
                            icon = new ImageIcon(BRKICONURL, partno);
                        }
                        s = makeStyleImageButton(icon, toolTip,1, chunk.getBytes());
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
     * create ChunkJButton for ImageIcon and add eventhandler.
     *
     * @param icon
     * @param toolTip
     * @param partno
     * @param chunk
     * @return
     */
    public Style makeStyleImageButton(ImageIcon icon, String toolTip, int partno, byte[] chunk) {
        String styleName = "ChunkImage" + partno;
        Style imageStyle = addOrGetStyle(styleName);
        StyleConstants.setAlignment(imageStyle, StyleConstants.ALIGN_CENTER);
        ChunkJbutton button = new ChunkJbutton(styleName, partno, chunk);
        button.setIcon(icon);
        button.setToolTipText(toolTip);
        button.setMargin(new Insets(0, 0, 0, 0));
        button.setActionCommand(styleName);
        button.addActionListener(
                e -> {
                    LOGGER4J.debug("button pressed:" + e.getActionCommand());
                });
        StyleConstants.setComponent(imageStyle, button);
        return imageStyle;
    }

    public Style getCRstyle() {
        Style CRstyle = this.addOrGetStyle(CRIMAGE_STYLENAME_PREFIX + counterCaridgeReturn++);
        //Style CRstyle = this.addOrGetStyle(CRIMAGE_STYLENAME_PREFIX);
        // component must always create per call setComponent.
        CaridgeReturnLabel crlabel = new CaridgeReturnLabel(CRstyle.getName(), "CR");
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
                LOGGER4J.error(ex.getMessage(), ex);
            }
        }
        if (cpos < totallen) {
            try {
                this.insertString(pos, text.substring(cpos, totallen), null);
            } catch (BadLocationException ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
        }
    }

    /**
     * Destroy and Create StyledDocument from RequestText and Chunks
     *
     * @param placeHolderStyleText PlaceHolderStyleText of Request
     * @param requestChunksNew if this value is null, internal this.requestChunks is used.
     */
    private void reCreateStyledDocFromRequestTextAndChunks(String placeHolderStyleText, List<RequestChunk> requestChunksNew) {

        if (requestChunksNew != null) {
            this.requestChunks = requestChunksNew;
        }

        if (placeHolderStyleText == null || placeHolderStyleText.isEmpty() || this.requestChunks == null) return;

            destroyDocumentAndRecreateStyles();

            int npos = -1;
            int cpos = 0;
            while ((npos = placeHolderStyleText.indexOf(CONTENTS_PLACEHOLDER_PREFIX, cpos)) != -1) {
                LOGGER4J.debug("CONTENTS_PLACEHOLDER_PREFIX found");
                if (npos > cpos) {
                    insertStringCR(this.getLength(), placeHolderStyleText.substring(cpos, npos));
                }
                cpos = npos;
                String element = CONTENTS_PLACEHOLDER_PREFIX;
                Style s = null;
                int pnopos = cpos + CONTENTS_PLACEHOLDER_PREFIX.length(); // partno start position
                if ((npos = placeHolderStyleText.indexOf(CONTENTS_PLACEHOLDER_SUFFIX, pnopos)) != -1) {
                    LOGGER4J.debug(
                            "CONTENTS_PLACEHOLDER_SUFFIX found npos,cpos="
                                    + npos
                                    + ","
                                    + pnopos
                                    + " ["
                                    + placeHolderStyleText.substring(pnopos, npos)
                                    + "]");
                    if (npos > pnopos && npos - pnopos <= PARTNO_MAXLEN) {
                        element =
                                CONTENTS_PLACEHOLDER_PREFIX
                                        + placeHolderStyleText.substring(pnopos, npos)
                                        + CONTENTS_PLACEHOLDER_SUFFIX;
                        LOGGER4J.debug("element[" + element + "]");
                        String nstr = placeHolderStyleText.substring(pnopos, npos).trim();
                        if (nstr.matches("[0-9]+")) {
                            int partno = Integer.parseInt(nstr);
                            String partnostr = Integer.toString(partno);
                            Optional<RequestChunk> ochunks =
                                    this.requestChunks.stream()
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
                                String toolTip = "Broken Data";
                                if (content_chunk.getChunkType() == RequestChunk.CHUNKTYPE.CONTENTS) {
                                    icon = new ImageIcon(BINICONURL, partnostr);
                                    toolTip = bundle.getString("ParmGenRegex.BinaryData.text");
                                } else { // diplayable image
                                    try {
                                        icon = new ImageIcon(content_chunk.getBytes(), partnostr);
                                        toolTip = "Image";
                                        LOGGER4J.debug("icon status:" + ImageIconLoadStatus(icon));
                                    } catch (Exception ex) {
                                        LOGGER4J.error(ex.getMessage(), ex);
                                    }
                                    if (icon.getImageLoadStatus() != MediaTracker.COMPLETE) {
                                        toolTip = bundle.getString("ParmGenRegex.BrokenData.text");
                                        icon = new ImageIcon(BRKICONURL, partnostr);
                                    }
                                }
                                s = makeStyleImageButton(icon, toolTip, partno, content_chunk.getBytes());
                            }
                        }
                    }
                }
                if (s != null) {
                    try {
                        LOGGER4J.debug("insert placeHolderSign s=" + (s == null ? "NULL" : "not null"));
                        this.insertString(this.getLength(), PLACE_HOLDER_SIGN, s);
                    } catch (BadLocationException ex) {
                        LOGGER4J.error(ex.getMessage(), ex);
                        element = "";
                    }
                } else {
                    insertStringCR(this.getLength(), element);
                }
                cpos += element.length();
            }
            if (cpos < placeHolderStyleText.length()) {
                insertStringCR(this.getLength(), placeHolderStyleText.substring(cpos, placeHolderStyleText.length()));
            }
    }

    public void printComponentsInThisDoc() {
        int pos = 0;
        int endPos = this.getLength();
        for(pos = 0; pos < endPos; pos++) {
            Element elm = this.getCharacterElement(pos);
            if (elm != null) {
                AttributeSet attrSet = elm.getAttributes();
                if (attrSet != null) {
                    String styleName = "";
                    // I can get StyleName and Component from the AttributeSet at last!
                    Object name = attrSet.getAttribute(AttributeSet.NameAttribute);
                    if (name != null) {
                        styleName = (String)name;
                    }
                    Component compo = StyleConstants.getComponent(attrSet);
                    if (compo != null) {
                        if (compo instanceof ChunkJbutton) {
                            ChunkJbutton button = (ChunkJbutton) compo;
                            LOGGER4J.debug("pos:" + pos +" style:[" + styleName + "] chunk partno:" + button.getPartNo() + " chunksize=" + button.getChunk().length);
                        }
                    }
                }
            }
        }
    }

    /**
     * get List of PlaceHolder which has JComponent characterAttribute in StyleDocument
     *
     * @return
     */
    public List<InterfacePlaceHolderStyle> getListOfPlaceHolderStyle() {
        int pos = 0;
        int endPos = this.getLength();
        List<InterfacePlaceHolderStyle> listOfPlaceHolderStyleChunk = new ArrayList<>();
        for(pos = 0; pos < endPos; pos++) {
            Element elm = this.getCharacterElement(pos);
            if (elm != null) {
                AttributeSet attrSet = elm.getAttributes();
                if (attrSet != null) {
                    String styleName = "";

                    // I can get StyleName and Component from the AttributeSet at last!
                    Object name = attrSet.getAttribute(AttributeSet.NameAttribute);
                    if (name != null) {
                        // character's styleName is overwrited each calling setCharacterAttributes.
                        // so below styleName is changed from original.
                        styleName = CastUtils.castToType(name);
                    }
                    Component compo = StyleConstants.getComponent(attrSet);
                    if (compo != null) {
                        if (compo instanceof ChunkJbutton) {
                            ChunkJbutton button = CastUtils.castToType(compo);
                            styleName = button.getStyleName();// must get original styleName
                            LOGGER4J.debug("pos:" + pos +" style:[" + styleName + "] chunk partno:" + button.getPartNo() + " chunksize=" + button.getChunk().length);
                            PlaceHolderStyleChunk placeHolderStyleChunk = new PlaceHolderStyleChunk(pos, styleName, button.getPartNo(), button.getChunk());
                            listOfPlaceHolderStyleChunk.add(placeHolderStyleChunk);
                        } else if (compo instanceof InterfaceCompoStyleName) {
                            InterfaceCompoStyleName compoStyle = (InterfaceCompoStyleName) compo;
                            styleName = compoStyle.getStyleName();
                            LOGGER4J.debug("pos:" + pos + " style:[" + styleName + "]");
                            PlaceHolderStyle placeHolderStyle = new PlaceHolderStyle(pos, styleName);
                            listOfPlaceHolderStyleChunk.add(placeHolderStyle);
                        }
                    }
                }
            }
        }
        return listOfPlaceHolderStyleChunk;
    }

    /**
     * is PlaceHolderComponet exist between startPos and endPos.
     *
     * @param startPos
     * @param endPos
     * @return
     */
    public boolean isExistPlaceHolderBetweenStartEndPos(int startPos, int endPos) {
        List<InterfacePlaceHolderStyle> placeHolderStyles = getListOfPlaceHolderStyle();
        for(InterfacePlaceHolderStyle placeHolderStyle: placeHolderStyles) {
            int placeHolderPos = placeHolderStyle.getPos();
            if (startPos <= placeHolderPos && placeHolderPos < endPos) {
                return true;
            }
        }
        return false;
    }

    /**
     *  get PlaceHolderStyleText from this content.
     *
     * @return PLaceHolderStyleText
     */
    public String getPlaceHolderStyledText() {
        try {
            StringBuffer resultBuffer = new StringBuffer();
            String originalText = this.getText(0, getLength());
            int lastPos = getLength();
            List<InterfacePlaceHolderStyle> listOfPlaceHolderStyle = getListOfPlaceHolderStyle();
            int stPos = 0;
            int endPos = -1;
            for(InterfacePlaceHolderStyle placeHolderStyle: listOfPlaceHolderStyle) {
                endPos = placeHolderStyle.getPos();
                resultBuffer.append(originalText.substring(stPos, endPos));
                if (placeHolderStyle instanceof PlaceHolderStyleChunk) {
                    PlaceHolderStyleChunk styleChunk = CastUtils.castToType(placeHolderStyle);
                    String placeHolder = CONTENTS_PLACEHOLDER_PREFIX + styleChunk.getPartNo() + CONTENTS_PLACEHOLDER_SUFFIX;
                    resultBuffer.append(placeHolder);
                } else {
                    resultBuffer.append(originalText.substring(endPos, endPos+1));
                }
                stPos = endPos + 1;
            }
            if (stPos < lastPos) {
                resultBuffer.append(originalText.substring(stPos, lastPos));
            }
            return resultBuffer.toString();

        }catch(Exception ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
        return null;
    }


    private String applyCustomConverter(boolean encode) {
        // convert decoded area to CustomEncode data
        String placeHolderStyleText = ZapUtil.urlDecodePartOfCustomEncodedText(this.getPlaceHolderStyledText());
        List<StartEndPosition> decodedAreaList =  DecoderTag.getDecodedStringList(placeHolderStyleText);
        StringBuffer encodedRequestText =  new StringBuffer();
        int outRangeStart = 0;
        for(StartEndPosition decodedArea: decodedAreaList) {
            if (outRangeStart < decodedArea.start) {
                encodedRequestText.append(placeHolderStyleText.substring(outRangeStart, decodedArea.start));
            }
            String decodedString = placeHolderStyleText.substring(decodedArea.start, decodedArea.end);
            String encodedString = decodedString;
            if (encode) {
                encodedString = CustomTagConverter.customEncode(decodedString);
            } else {
                encodedString = CustomTagConverter.customDecode(decodedString);
            }
            LOGGER4J.debug("original[" + decodedString + "] " + (encode?"encoded":"decoded") + "[" + encodedString + "]");
            encodedRequestText.append(encodedString);
            outRangeStart = decodedArea.end;
        }
        if (outRangeStart < placeHolderStyleText.length()) {
            encodedRequestText.append(placeHolderStyleText.substring(outRangeStart, placeHolderStyleText.length()));
        }
        return encodedRequestText.toString();
    }


    /**
     * get CustomDeocded PlaceHolderStyledText
     * @return custom decoded PLaceHolderStyledText
     */
    public String getDecodedPlaceHolderStyledText() {
        return applyCustomConverter(false);
    }

    /**
     * get CustomEncoded PLaceHolderStyledText
     * @return custom encoded PlaceHolderStyledText
     */
    public String getEncodedPlaceHolderStyledText() {
        return applyCustomConverter(true);
    }

    /**
     * get Original Encoded PRequest
     *
     * @param pRequest
     * @return
     */
    public PRequest getOriginalEncodedPRequest(PRequest pRequest) {

        enc = pRequest.getPageEnc();
        host = pRequest.getHost();
        port = pRequest.getPort();
        isSSL = pRequest.isSSL();
        updateRequest(pRequest);

        Encode enc = pRequest.getPageEnc();

        String placeHolderStyledText = getDecodedPlaceHolderStyledText();
        String originalEncodedPlaceHolderStyledText = DecoderTag.getOriginalEncodedString(placeHolderStyledText, enc);


        return reBuildPRequestFromDocTextAndChunks(originalEncodedPlaceHolderStyledText);
    }

    public Encode getEnc() {
        return this.enc;
    }

    public boolean getDocumentFilterMasked() {
        return this.documentFilterMasked;
    }
}


