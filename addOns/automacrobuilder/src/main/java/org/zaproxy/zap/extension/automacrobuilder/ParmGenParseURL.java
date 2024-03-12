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

/** @author gdgd009xcd */
public class ParmGenParseURL {
    String protocol = "";
    String domain = "";
    String path = "";
    String args = "";
    ArrayList<String[]> nvpairs = null;

    public ParmGenParseURL(String url) {
        nvpairs = new ArrayList<String[]>();
        if (url != null) {

            String[] urlist = url.split("/");
            int k = 0;
            protocol = "";
            domain = "";
            String pathwithargs = "";
            for (String u : urlist) {
                switch (k) {
                    case 0:
                        if (u.toLowerCase().startsWith("https")) {
                            protocol = "http";
                        } else if (u.toLowerCase().startsWith("http")) {
                            protocol = "https";
                        } else {

                            pathwithargs = u;
                        }
                        break;
                    case 1:
                        if (protocol.isEmpty()) {
                            pathwithargs += "/";
                            pathwithargs += u;
                        }
                        break;
                    case 2:
                        if (!protocol.isEmpty()) {
                            domain = u;
                        } else {
                            pathwithargs += "/";
                            pathwithargs += u;
                        }
                        break;
                    default:
                        pathwithargs += "/";
                        pathwithargs += u;
                        break;
                }
                k++;
            }

            String[] argslist = pathwithargs.split("[&?]|amp;");
            int i = 0;

            for (String v : argslist) {
                if (i == 0) {
                    path = v;
                    // if(url.endsWith("/")){
                    //    path += "/";
                    // }
                } else {
                    String[] nvp = v.split("=");

                    if (nvp != null) {
                        if (nvp.length == 1) {
                            if (v.endsWith("=")) {
                                String[] nvstr = new String[2];
                                nvstr[0] = nvp[0];
                                nvstr[1] = "";
                                nvp = nvstr;
                            }
                        }
                        if (nvp.length >= 1) {
                            if (!nvp[0].isEmpty()) {
                                nvpairs.add(nvp);
                            }
                        }
                    }
                }
                i++;
            }
        }
    }

    String getDomain() {
        return domain;
    }

    String getProtocol() {
        return protocol;
    }

    public String getPath() {
        return path;
    }

    int getArgsLen() {
        return nvpairs.size();
    }

    ArrayList<String[]> getArgsList() {
        return nvpairs;
    }
}
