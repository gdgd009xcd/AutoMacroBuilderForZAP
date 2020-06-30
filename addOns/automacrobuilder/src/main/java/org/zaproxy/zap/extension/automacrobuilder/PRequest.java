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

public class PRequest extends ParseHTTPHeaders {

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
}
