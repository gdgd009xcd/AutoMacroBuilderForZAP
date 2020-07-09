/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder;

import java.nio.charset.Charset;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;

@SuppressWarnings({"unchecked", "serial"})
public class StyledDocumentWithChunk extends DefaultStyledDocument {
    Encode enc = null;
    String host;
    int port;
    boolean isSSL;
    List<PRequest.RequestChunk> requestChunks = null;
    List<PResponse.ResponseChunk> responseChunks = null;

    StyledDocumentWithChunk(PRequest prequest) {
        super();
        enc = prequest.getPageEnc();
        host = prequest.getHost();
        port = prequest.getPort();
        isSSL = prequest.isSSL();
        requestChunks = prequest.getRequestChunks();
    }

    StyledDocumentWithChunk(PResponse presponse) {
        super();
        enc = presponse.getPageEnc();
        responseChunks = presponse.getResponseChunks();
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
     * Rebuild PRequest from Doc text and Chunks.
     *
     * @return
     */
    public PRequest reBuildPRequestFromDocText() {
        try {
            String text = this.getText(0, getLength());
            Charset charset = enc.getIANACharset();
            byte[] docbytes = text.getBytes(charset);
            ParmGenBinUtil contarray = new ParmGenBinUtil(docbytes);
            ParmGenBinUtil resultarray = new ParmGenBinUtil();
            byte[] PLS_PREFIX = ParmGenTextDoc.CONTENTS_PLACEHOLDER_PREFIX.getBytes();
            byte[] PLS_SUFFIX = ParmGenTextDoc.CONTENTS_PLACEHOLDER_SUFFIX.getBytes();
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
}
