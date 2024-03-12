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

import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

public class PResponse extends ParseHTTPHeaders {
    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private ParmGenHashMap map = null;
    private ParmGenParser htmlparser = null;
    private ParmGenGSONDecoder jsonparser = null;

    public static final int MAX_SIZE_RESPONSE_CONTENTS = 25000;
    private static final int MAX_SIZE_DISPLAYABLE_TEXTS = 100000;

    public PResponse(byte[] bin, Encode _pageenc) {
        super(bin, _pageenc);
        map = null;
        htmlparser = null;
        jsonparser = null;
    }

    // get Location header value
    public <T> InterfaceCollection<T> getLocationTokens(InterfaceCollection<T> tklist) {
        String locheader = getHeader("Location");

        if (locheader != null) {
            String[] nvpairs = locheader.split("[?&]");
            String url = nvpairs[0];
            for (String tnv : nvpairs) {
                String[] nvp = tnv.split("=");
                String name = nvp[0];
                String value = new String("");
                if (nvp.length > 1) {
                    value = nvp[1];

                    if (name != null && name.length() > 0 && value != null) {
                        tklist.addToken(
                                AppValue.TokenTypeNames.LOCATION, url, name, value, false, 0);
                    }
                }
            }
            if (tklist != null && tklist.size() > 0) {
                return tklist;
            }
        }
        return null;
    }

    public ParmGenToken fetchNameValue(String name, AppValue.TokenTypeNames _tokentype, int fcnt) {
        if (map == null) {
            map = new ParmGenHashMap();
            InterfaceCollection<Entry<ParmGenTokenKey, ParmGenTokenValue>> ic =
                    getLocationTokens(map);
            // String subtype = getContent_Subtype();
            switch (_tokentype) {
                case JSON:
                    jsonparser = new ParmGenGSONDecoder(getBodyStringWithoutHeader());
                    break;
                default:
                    htmlparser = new ParmGenParser(getBodyStringWithoutHeader());
                    break;
            }
            /**
             * if(subtype!=null&&subtype.toLowerCase().equals("json")){ jsonparser = new
             * ParmGenJSONDecoder(body); }else{ htmlparser = new ParmGenParser(body); }*
             */
        } else {
            switch (_tokentype) {
                case JSON:
                    if (jsonparser == null) {
                        jsonparser = new ParmGenGSONDecoder(getBodyStringWithoutHeader());
                    }
                    break;
                default:
                    if (htmlparser == null) {
                        htmlparser = new ParmGenParser(getBodyStringWithoutHeader());
                    }
                    break;
            }
        }
        ParmGenTokenKey tkey = new ParmGenTokenKey(_tokentype, name, fcnt);
        ParmGenTokenValue tval = map.get(tkey);
        if (tval != null) {
            return new ParmGenToken(tkey, tval);
        }
        switch (_tokentype) {
            case JSON:
                if (jsonparser != null) {
                    return jsonparser.fetchNameValue(name, fcnt, _tokentype);
                }
                break;
            default:
                if (htmlparser != null) {
                    return htmlparser.fetchNameValue(name, fcnt, _tokentype);
                }
                break;
        }

        return null;
    }

    public PResponse clone() {
        PResponse nobj = (PResponse) super.clone();
        // private ParmGenHashMap map = null;
        nobj.map = this.map != null ? this.map.clone() : null;
        // private ParmGenParser htmlparser = null;
        nobj.htmlparser = this.htmlparser != null ? this.htmlparser.clone() : null;
        // private ParmGenGSONDecoder jsonparser =null;
        nobj.jsonparser = this.jsonparser != null ? this.jsonparser.clone() : null;

        return nobj;
    }

    public static class ResponseChunk {
        public enum CHUNKTYPE {
            RESPONSEHEADER, // HEADER<CR><LF>HEADER<CRLF><CRLF>
            CONTENTSBINARY, // [binary] no displayable
            CONTENTSIMG, // displayable image
            CONTENTS, // displayable normal contents.
        };

        CHUNKTYPE ctype;
        byte[] data;

        ResponseChunk(CHUNKTYPE ctype, byte[] data) {
            this.ctype = ctype;
            this.data = data;
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
    }

    /**
     * Get List<ResponseChunk> which is parsed request contents representation
     *
     * @return
     */
    public List<PResponse.ResponseChunk> getResponseChunks() {
        String theaders = getHeaderOnly();
        byte[] tbodies = getBodyBytes();
        String tcontent_type = getHeader("Content-Type");
        return getResponseChunks(theaders, tbodies, tcontent_type);
    }

    private List<PResponse.ResponseChunk> getResponseChunks(
            String theaders, byte[] tbodies, String tcontent_type) {
        List<PResponse.ResponseChunk> reschunks = new ArrayList<>();

        String mediaType = getContentMimeType();
        String displayableImageContents = "";
        String application_json_contents = "";
        String text_contents = "";
        if (tcontent_type != null && !tcontent_type.isEmpty()) {
            LOGGER4J.debug("content-type[" + tcontent_type + "]");
            List<String> matches =
                    ParmGenUtil.getRegexMatchGroups("image/(jpeg|png|gif)", tcontent_type);
            if (matches.size() > 0) {
                displayableImageContents = matches.get(0);
            }
            List<String> jsonmatches =
                    ParmGenUtil.getRegexMatchGroups("application/(json|javascript)", tcontent_type);
            if (jsonmatches.size() > 0) {
                application_json_contents = jsonmatches.get(0);
            }
            List<String> textmatches =
                    ParmGenUtil.getRegexMatchGroups("application/(\\w)", tcontent_type);
            if (jsonmatches.size() > 0) {
                application_json_contents = jsonmatches.get(0);
            }
        }

        boolean displayableTextContents = false;
        if (tbodies != null && tbodies.length < MAX_SIZE_DISPLAYABLE_TEXTS) {
            if (mediaType.equalsIgnoreCase("text/html")) {
                displayableTextContents = true;
            } else if (!application_json_contents.isEmpty()) {
                displayableTextContents = true;
            }
        }

        int partno = 0;
        // create responseheader chunk
        PResponse.ResponseChunk chunk =
                new PResponse.ResponseChunk(
                        PResponse.ResponseChunk.CHUNKTYPE.RESPONSEHEADER, theaders.getBytes());
        reschunks.add(chunk);

        // create body chunk
        PResponse.ResponseChunk.CHUNKTYPE chntype = PResponse.ResponseChunk.CHUNKTYPE.CONTENTS;
        if (!displayableImageContents.isEmpty()) {
            chntype = PResponse.ResponseChunk.CHUNKTYPE.CONTENTSIMG;
        } else if (tbodies != null
                && tbodies.length > MAX_SIZE_RESPONSE_CONTENTS
                && !displayableTextContents) {
            chntype = PResponse.ResponseChunk.CHUNKTYPE.CONTENTSBINARY;
        }

        if (tbodies != null && tbodies.length > 0) {
            PResponse.ResponseChunk chunkbody = new PResponse.ResponseChunk(chntype, tbodies);
            reschunks.add(chunkbody);
            LOGGER4J.debug("res body size:" + chunkbody.getBytes().length);
        } else {
            LOGGER4J.debug("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!res body is null");
        }
        return reschunks;
    }
}
