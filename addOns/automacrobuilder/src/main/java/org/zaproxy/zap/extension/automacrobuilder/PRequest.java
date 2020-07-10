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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PRequest extends ParseHTTPHeaders {

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public PRequest(String h, int p, boolean ssl, byte[] _binmessage, Encode _pageenc) {
        super(h, p, ssl, _binmessage, _pageenc);
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
        return nobj;
    }

    public static class RequestChunk {
        public enum CHUNKTYPE {
            REQUESTHEADER, // HEADER<CR><LF>HEADER<CRLF><CRLF>
            BOUNDARY, // -----------------------------178155009418426923672012858312<CR><LF>
            BOUNDARYHEADER, // Content-Disposition: form-data; name="imgfile";
            // filename="romischenreiches.jpg"<CR><LF>Content-Type:
            // image/jpeg<CR><LF><CR><LF>
            CONTENTS, // [binary](without CONTENTSEND)
            CONTENTSEND, // <CR><LF>
            LASTBOUNDARY, // -----------------------------178155009418426923672012858312--<CR><LF>
        };

        CHUNKTYPE ctype;
        byte[] data;
        int partno;

        RequestChunk(CHUNKTYPE ctype, byte[] data, int partno) {
            this.ctype = ctype;
            this.data = data;
            this.partno = partno;
        }

        /**
         * Get getChunkType
         *
         * @return
         */
        public CHUNKTYPE getChunkType() {
            return this.ctype;
        }

        /**
         * Get byte data
         *
         * @return
         */
        public byte[] getBytes() {
            return this.data;
        }

        /**
         * multi-part number from 0
         *
         * @return
         */
        public int getPartNo() {
            return this.partno;
        }
    }

    /**
     * Get List<RequestChunk> which is parsed request contents representation
     *
     * @return
     */
    public List<RequestChunk> getRequestChunks() {
        String theaders = getHeaderOnly();
        byte[] tbodies = getBodyBytes();
        String tcontent_type = getHeader("Content-Type");
        return getRequestChunks(theaders, tbodies, tcontent_type);
    }

    public List<RequestChunk> getRequestChunks(
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
                new RequestChunk(
                        PRequest.RequestChunk.CHUNKTYPE.REQUESTHEADER, theaders.getBytes(), partno);
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
                    if (hend != -1
                            && hend >= cpos
                            && hend + headerseparator.length
                                    <= npos) { // at least , CRLFCRLF found between boundary.
                        byte[] boundaryheader =
                                _contarray.subBytes(
                                        cpos, hend + headerseparator.length); // mutipart headers
                        chunk =
                                new RequestChunk(
                                        PRequest.RequestChunk.CHUNKTYPE.BOUNDARYHEADER,
                                        boundaryheader,
                                        partno);
                        reqchunks.add(chunk);
                    } else { // no header.
                        contstartpos = cpos;
                    }

                    int contendpos = npos - 2;
                    if (contendpos > contstartpos) {
                        byte[] contents = _contarray.subBytes(contstartpos, contendpos);
                        chunk =
                                new RequestChunk(
                                        PRequest.RequestChunk.CHUNKTYPE.CONTENTS, contents, partno);
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
                                        PRequest.RequestChunk.CHUNKTYPE.CONTENTSEND,
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
                                        PRequest.RequestChunk.CHUNKTYPE.LASTBOUNDARY,
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
                                        PRequest.RequestChunk.CHUNKTYPE.BOUNDARY,
                                        boundarybytescrlf,
                                        partno);
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
                                    PRequest.RequestChunk.CHUNKTYPE.BOUNDARY,
                                    boundarybytes,
                                    partno);
                    reqchunks.add(chunk);
                }
            }
            if (cpos < tbodies.length) {
                partno++;
                byte[] gabagebytes = _contarray.subBytes(cpos, tbodies.length);
                chunk =
                        new RequestChunk(
                                PRequest.RequestChunk.CHUNKTYPE.CONTENTS, gabagebytes, partno);
                reqchunks.add(chunk);
            }
        } else { // simple request. headers<CR><LF>contents.
            if (tbodies != null && tbodies.length > 0) {
                chunk = new RequestChunk(PRequest.RequestChunk.CHUNKTYPE.CONTENTS, tbodies, partno);
                reqchunks.add(chunk);
            }
        }

        return reqchunks;
    }
}
