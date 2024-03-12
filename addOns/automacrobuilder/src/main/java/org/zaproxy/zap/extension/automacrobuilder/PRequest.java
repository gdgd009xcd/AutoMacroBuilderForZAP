/*
 * Copyright 2024 gdgd009xcd
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

import org.zaproxy.zap.extension.automacrobuilder.view.StyledDocumentWithChunk;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.text.BadLocationException;

public class PRequest extends ParseHTTPHeaders {

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    // @Deprecated(since = "1.2", forRemoval = true) 20240229 since no need hold chunks in this PRequest.
    private List<RequestChunk> chunks = null;
    // @Deprecated(since = "1.2", forRemoval = true) 20240229 since no need hold doctext in this PRequest.
    private String doctext = null;

    public PRequest(String h, int p, boolean ssl, byte[] _binmessage, Encode _pageenc) {
        super(h, p, ssl, _binmessage, _pageenc);
    }

    /**
     * create instance
     * pass argument chunkdoc, extract doctext from chunkdoc
     *
     * @Deprecated 20240229 since no need hold chunks/doctext in this PRequest.
     *
     * @param h
     * @param p
     * @param ssl
     * @param _binmessage
     * @param _pageenc
     * @param chunkdoc
     */
    @Deprecated(since = "1.2", forRemoval = true)
    PRequest(
            String h,
            int p,
            boolean ssl,
            byte[] _binmessage,
            Encode _pageenc,
            StyledDocumentWithChunk chunkdoc) {
        super(h, p, ssl, _binmessage, _pageenc);
        if (chunkdoc != null) {
            chunks = chunkdoc.getRequestChunks();
            doctext = chunkdoc.getPlaceHolderStyleText();
        }
    }

    public PRequest newRequestWithRemoveSpecialChars(String regex) { // remove section chars
        byte[] binmessage = getByteMessage();
        String isomessage = new String(binmessage, StandardCharsets.ISO_8859_1);
        String defaultregex = "[§]";
        if (regex != null && !regex.isEmpty()) {
            defaultregex = regex;
        }
        String rawmessage = isomessage.replaceAll(defaultregex, "");
        String host = getHost();
        int port = getPort();
        boolean isSSL = isSSL();
        Encode penc = getPageEnc();
        return new PRequest(
                host, port, isSSL, rawmessage.getBytes(StandardCharsets.ISO_8859_1), penc);
    }

    @Override
    public PRequest clone() {
        PRequest nobj = (PRequest) super.clone();
        nobj.chunks = ListDeepCopy.listDeepCopyRequestChunk(this.chunks);
        return nobj;
    }

    /**
     * Get List<RequestChunk> which is parsed request contents representation
     *
     * @Deprecated 20240229 since no need hold chunks/doctext in this PRequest.
     *
     * @return
     */
    @Deprecated(since = "1.2", forRemoval = true)
    public List<RequestChunk> getRequestChunks() {
        if (this.chunks == null) {
            String theaders = getHeaderOnly();
            byte[] tbodies = getBodyBytes();
            String tcontent_type = getHeader("Content-Type");
            this.chunks = getRequestChunks(theaders, tbodies, tcontent_type);
        }
        return this.chunks;
    }

    /**
     * generate List<RequestChunk> which is parsed request contents representation
     * @return
     */
    public List<RequestChunk> generateRequestChunks() {
        List<RequestChunk> chunks;
        String theaders = getHeaderOnly();
        byte[] tbodies = getBodyBytes();
        String tcontent_type = getHeader("Content-Type");
        chunks = getRequestChunks(theaders, tbodies, tcontent_type);
        return chunks;
    }

    /**
     * set doc text from StyledDocumentWithChunks(representating for PRequest)
     *
     * @Deprecated 20240229 since no need hold chunks/doctext in this PRequest.
     *
     * @param doc
     */
    @Deprecated(since = "1.2", forRemoval = true)
    public void setDocText(StyledDocumentWithChunk doc) {
        this.doctext = doc.getPlaceHolderStyleText();
    }

    /**
     * @Deprecated 20240229 since no need hold chunks/doctext in this PRequest.
     *
     * @return
     */
    @Deprecated(since = "1.2", forRemoval = true)
    public String getDocText() {
        return this.doctext;
    }

    /**
     * get PrimeHeader except tailing CRLF
     */
    public String getPrimeHeaderWithoutCRLF() {
        return super.getStartline();
    }

    private List<RequestChunk> getRequestChunks(
            String theaders, byte[] tbodies, String tcontent_type) {
        List<RequestChunk> reqchunks = new ArrayList<>();
        byte[] headerseparator = {0x0d, 0x0a, 0x0d, 0x0a}; // <CR><LF><CR><LF>

        String tboundarywithoutcrlf = null;
        Charset charset = getPageEnc().getIANACharset();

        if (tcontent_type != null && !tcontent_type.isEmpty()) {
            Pattern tctypepattern =
                    ParmGenUtil.Pattern_compile("multipart/form-data;.*?boundary=(.+)$");

            Matcher tctypematcher = tctypepattern.matcher(tcontent_type);
            if (tctypematcher.find()) {
                String baseboundary = tctypematcher.group(1);
                tboundarywithoutcrlf = "--" + baseboundary;
                // form-data
            }
        }

        int endOfData = tbodies != null ? tbodies.length : 0;
        int partno = 0;
        // create requestheader chunks
        byte[] reqheaderchunks = theaders.getBytes();
        RequestChunk chunk =
                new RequestChunk(RequestChunk.CHUNKTYPE.REQUESTHEADER, theaders.getBytes(), partno);
        reqchunks.add(chunk);

        if (tboundarywithoutcrlf != null && !tboundarywithoutcrlf.isEmpty()) { // form-data
            ParmGenBinUtil boundaryarraywithoutcrlf =
                    new ParmGenBinUtil(tboundarywithoutcrlf.getBytes());
            String baseboundarycrlf = tboundarywithoutcrlf + "\r\n";
            ParmGenBinUtil boundaryarraycrlf = new ParmGenBinUtil(baseboundarycrlf.getBytes());
            String lastboundarycrlf = tboundarywithoutcrlf + "--\r\n";
            ParmGenBinUtil lastboundaryarraycrlf = new ParmGenBinUtil(lastboundarycrlf.getBytes());
            ParmGenBinUtil _contarray = new ParmGenBinUtil(tbodies);
            int npos = -1;
            int cpos = 0;
            while ((npos = _contarray.indexOf(boundaryarraywithoutcrlf.getBytes(), cpos)) != -1) {
                if (cpos > 0) {
                    int hend = _contarray.indexOf(headerseparator, cpos);
                    int contstartpos = hend + headerseparator.length;
                    String displayableimgtype = "";
                    if (hend != -1
                            && hend >= cpos
                            && hend + headerseparator.length
                                    <= npos) { // at least , CRLFCRLF found between boundary.
                        byte[] boundaryheader =
                                _contarray.subBytes(
                                        cpos, hend + headerseparator.length); // mutipart headers
                        chunk =
                                new RequestChunk(
                                        RequestChunk.CHUNKTYPE.BOUNDARYHEADER,
                                        boundaryheader,
                                        partno);
                        reqchunks.add(chunk);
                        String header = new String(chunk.getBytes());
                        List<String> matches =
                                ParmGenUtil.getRegexMatchGroups(
                                        "Content-Type: image/(jpeg|png|gif)", header);
                        if (matches.size() > 0) {
                            displayableimgtype = matches.get(0);
                        }
                    } else { // no header.
                        contstartpos = cpos;
                    }

                    int contendpos = npos - 2;
                    if (contendpos > contstartpos) {
                        RequestChunk.CHUNKTYPE chunktype =
                                displayableimgtype.isEmpty()
                                        ? RequestChunk.CHUNKTYPE.CONTENTS
                                        : RequestChunk.CHUNKTYPE.CONTENTSIMG;
                        byte[] contents = _contarray.subBytes(contstartpos, contendpos);
                        chunk = new RequestChunk(chunktype, contents, partno);
                        reqchunks.add(chunk);
                    } else if (npos > contstartpos) { // No CONTENT but has CONTENTSEND.
                        contendpos = contstartpos;
                    } else { // has No CONTENT and CONTENDEND
                        contendpos = -1;
                    }

                    if (contendpos != -1) {
                        byte[] contentsendbytes = _contarray.subBytes(contendpos, npos);
                        chunk =
                                new RequestChunk(
                                        RequestChunk.CHUNKTYPE.CONTENTSEND,
                                        contentsendbytes,
                                        partno);
                        reqchunks.add(chunk);
                    }

                    partno++;
                    int nextcpos = npos + boundaryarraywithoutcrlf.length() + 2;
                    String lasthyphen = "";
                    byte[] lasthyphenbytes = _contarray.subBytes(nextcpos - 2, nextcpos);
                    if (lasthyphenbytes != null && lasthyphenbytes.length == 2) {
                        lasthyphen = new String(lasthyphenbytes, charset);
                        byte[] endcrlfbytes = _contarray.subBytes(nextcpos, nextcpos + 2);
                        if (endcrlfbytes != null && endcrlfbytes.length == 2) {
                            String endcrlf = new String(endcrlfbytes, charset);
                            lasthyphen = lasthyphen + endcrlf;
                        }
                    }

                    LOGGER4J.debug(
                            "crlforlasthyphon[" + lasthyphen.replaceAll("\r\n", "<CR><LF>") + "]");
                    if (lasthyphen.startsWith("--")) {
                        if (lasthyphen.equals("--\r\n")) {
                            nextcpos += 2;
                        }
                        byte[] lastboundarybytescrlf = _contarray.subBytes(npos, nextcpos);
                        // last hyphon "--" + CRLF
                        chunk =
                                new RequestChunk(
                                        RequestChunk.CHUNKTYPE.LASTBOUNDARY,
                                        lastboundarybytescrlf,
                                        partno);
                        reqchunks.add(chunk);
                    } else {
                        if (!lasthyphen.equals("\r\n")) {
                            nextcpos -= 2;
                        }
                        byte[] boundarybytescrlf = _contarray.subBytes(npos, nextcpos);
                        chunk =
                                new RequestChunk(
                                        RequestChunk.CHUNKTYPE.BOUNDARY, boundarybytescrlf, partno);
                        reqchunks.add(chunk);
                    }
                    cpos = nextcpos;
                } else {
                    cpos = npos + boundaryarraywithoutcrlf.length() + 2;
                    byte[] bytescrlf = _contarray.subBytes(npos - 2, npos);
                    String crlf = "";
                    if (bytescrlf != null && bytescrlf.length == 2) {
                        crlf = new String(bytescrlf, charset);
                    }
                    if (!crlf.equals("\r\n")) {
                        cpos -= 2;
                    }
                    byte[] boundarybytes = _contarray.subBytes(npos, cpos);
                    chunk =
                            new RequestChunk(
                                    RequestChunk.CHUNKTYPE.BOUNDARY, boundarybytes, partno);
                    reqchunks.add(chunk);
                }
            }
            if (cpos < tbodies.length) {
                partno++;
                byte[] gabagebytes = _contarray.subBytes(cpos, tbodies.length);
                chunk = new RequestChunk(RequestChunk.CHUNKTYPE.CONTENTS, gabagebytes, partno);
                reqchunks.add(chunk);
            }
        } else { // simple request. headers<CR><LF>contents.
            if (tbodies != null && tbodies.length > 0) {
                chunk = new RequestChunk(RequestChunk.CHUNKTYPE.CONTENTS, tbodies, partno);
                reqchunks.add(chunk);
            }
        }

        return reqchunks;
    }

    /**
     * update DocText and Chunks with specified chunks
     *
     * @Deprecated 20240229 since no need hold chunks/doctext in this PRequest.
     *
     * @param orgchunks
     */
    @Deprecated(since = "1.2", forRemoval = true)
    void updateDocAndChunks(List<RequestChunk> orgchunks) {

        if (orgchunks == null) return;
        // recreate this doctext and chunks from prequest.getBytes();
        this.chunks = null;
        this.doctext = null;
        StyledDocumentWithChunk nouseddoc = new StyledDocumentWithChunk(this);

        Charset charset = getPageEnc().getIANACharset();
        int npos = -1;
        int cpos = 0;
        int placebegin = 0;
        while ((npos =
                        this.doctext.indexOf(
                                StyledDocumentWithChunk.CONTENTS_PLACEHOLDER_PREFIX, cpos))
                != -1) {
            placebegin = npos;
            cpos = npos + StyledDocumentWithChunk.CONTENTS_PLACEHOLDER_PREFIX.length();
            int beginpos = cpos;
            if ((npos =
                            this.doctext.indexOf(
                                    StyledDocumentWithChunk.CONTENTS_PLACEHOLDER_SUFFIX, cpos))
                    != -1) {
                cpos = npos + StyledDocumentWithChunk.CONTENTS_PLACEHOLDER_SUFFIX.length();
                int endpos = npos;
                if (endpos - beginpos <= StyledDocumentWithChunk.PARTNO_MAXLEN) {
                    String partno = this.doctext.substring(beginpos, endpos).trim();
                    if (partno != null && partno.length() > 0) {
                        int pno = Integer.parseInt(partno);
                        if (pno > -1) {
                            Optional<RequestChunk> optorgchunk =
                                    orgchunks.stream()
                                            .filter(
                                                    c ->
                                                            c.getPartNo() == pno
                                                                    && (c.getChunkType()
                                                                                    == RequestChunk
                                                                                            .CHUNKTYPE
                                                                                            .CONTENTS
                                                                            || c.getChunkType()
                                                                                    == RequestChunk
                                                                                            .CHUNKTYPE
                                                                                            .CONTENTSIMG))
                                            .findFirst();
                            RequestChunk orgchunk = optorgchunk.orElse(null);
                            Optional<RequestChunk> optnewchunk =
                                    this.chunks.stream()
                                            .filter(
                                                    c ->
                                                            c.getPartNo() == pno
                                                                    && (c.getChunkType()
                                                                                    == RequestChunk
                                                                                            .CHUNKTYPE
                                                                                            .CONTENTS
                                                                            || c.getChunkType()
                                                                                    == RequestChunk
                                                                                            .CHUNKTYPE
                                                                                            .CONTENTSIMG))
                                            .findFirst();
                            RequestChunk newchunk = optnewchunk.orElse(null);
                            if (orgchunk != null && newchunk != null) {
                                ParmGenBinUtil newarray = new ParmGenBinUtil(newchunk.getBytes());
                                byte[] orgdata = orgchunk.getBytes();
                                int stp = -1;
                                int etp = 0;
                                if ((stp = newarray.indexOf(orgdata)) != -1) {
                                    byte[] newdata = newarray.getBytes();
                                    int newdatalen = newdata.length;
                                    etp = stp + orgdata.length;
                                    String prefix = "";
                                    String suffix = "";
                                    if (stp > 0) {
                                        prefix = new String(newarray.subBytes(0, stp), charset);
                                    }
                                    if (etp < newdatalen) {
                                        suffix =
                                                new String(
                                                        newarray.subBytes(etp, newdatalen),
                                                        charset);
                                    }
                                    this.doctext =
                                            this.doctext.substring(0, placebegin)
                                                    + prefix
                                                    + this.doctext.substring(placebegin, cpos)
                                                    + suffix
                                                    + this.doctext.substring(cpos);
                                    cpos += prefix.length() + suffix.length();
                                    LOGGER4J.debug(
                                            "prefix["
                                                    + prefix
                                                    + "] chunk.len:"
                                                    + orgchunk.getBytes().length
                                                    + " suffix["
                                                    + suffix
                                                    + "]");
                                    newchunk.setByte(orgchunk.getBytes());
                                    newchunk.setChunkType(orgchunk.getChunkType());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
