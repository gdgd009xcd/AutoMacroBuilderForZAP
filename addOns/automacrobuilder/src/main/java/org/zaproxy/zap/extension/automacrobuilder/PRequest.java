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
                    byte[] boundaryheader =
                            _contarray.subBytes(
                                    cpos, hend + headerseparator.length); // mutipart headers
                    chunk =
                            new RequestChunk(
                                    PRequest.RequestChunk.CHUNKTYPE.BOUNDARYHEADER,
                                    boundaryheader,
                                    partno);
                    reqchunks.add(chunk);
                    int contstartpos = hend + headerseparator.length;
                    int contendpos = npos - 2;
                    if (contendpos > contstartpos) {
                        byte[] contents = _contarray.subBytes(contstartpos, contendpos);
                        chunk =
                                new RequestChunk(
                                        PRequest.RequestChunk.CHUNKTYPE.CONTENTS, contents, partno);
                        reqchunks.add(chunk);
                    }
                    chunk =
                            new RequestChunk(
                                    PRequest.RequestChunk.CHUNKTYPE.CONTENTSEND,
                                    "\r\n".getBytes(),
                                    partno);
                    reqchunks.add(chunk);

                    partno++;
                    int nextcpos = npos + boundaryarraywithoutcrlf.length() + 2;
                    String lasthyphon = new String(_contarray.subBytes(nextcpos - 2, nextcpos));
                    String lasthyphonrepesentation = "--";
                    LOGGER4J.debug("lasthyphon[" + lasthyphon.replaceAll("\r\n", "<CR><LF>") + "]");
                    if (lasthyphon.equals(lasthyphonrepesentation)) {
                        // last hyphon "--" + CRLF
                        chunk =
                                new RequestChunk(
                                        PRequest.RequestChunk.CHUNKTYPE.LASTBOUNDARY,
                                        lastboundaryarraycrlf.getBytes(),
                                        partno);
                        reqchunks.add(chunk);
                        break;
                    } else {
                        LOGGER4J.debug(
                                "lasthyphon["
                                        + lasthyphon.replaceAll("\r\n", "<CR><LF>")
                                        + "]!="
                                        + lasthyphonrepesentation);
                        chunk =
                                new RequestChunk(
                                        PRequest.RequestChunk.CHUNKTYPE.BOUNDARY,
                                        boundaryarraycrlf.getBytes(),
                                        partno);
                        reqchunks.add(chunk);
                    }
                    cpos = nextcpos;
                } else {
                    cpos = npos + boundaryarraywithoutcrlf.length() + 2;
                    chunk =
                            new RequestChunk(
                                    PRequest.RequestChunk.CHUNKTYPE.BOUNDARY,
                                    boundaryarraycrlf.getBytes(),
                                    partno);
                    reqchunks.add(chunk);
                }
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
