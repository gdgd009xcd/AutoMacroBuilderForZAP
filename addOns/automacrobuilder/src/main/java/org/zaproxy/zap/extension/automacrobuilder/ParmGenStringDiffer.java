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

import java.util.ArrayList;
import java.util.List;

/** @author gdgd009xcd */
public class ParmGenStringDiffer {
    String org;
    String mod;
    int mod_length = -1;
    int org_length = -1;
    boolean orgmatchall = false;

    ParmGenStringDiffer(String _orig, String _mod) {
        org = _orig;
        mod = _mod;
    }

    ArrayList<ParmGenString> analyze() {
        ArrayList<ParmGenString> strlist = new ArrayList<ParmGenString>();
        orgmatchall = false;
        int s = 0;
        int e = 0;
        int m_s = -1;
        int m_e = 0;
        int n_m_s = -1;
        int n_m_e = 0;
        int o_s = 0;
        int o_e = 0;
        mod_length = mod.length();
        org_length = org.length();

        boolean matched = false;
        for (s = 0; s <= mod_length; s++) {
            String part = null;
            try {
                e = s + 1;
                part = mod.substring(s, e);
            } catch (IndexOutOfBoundsException ex) {
                part = null;
            }
            String org_part = null;
            try {
                o_e = o_s + 1;
                org_part = org.substring(o_s, o_e);
            } catch (IndexOutOfBoundsException ex) {
                org_part = null;
            }

            if (org_part == null || part == null) break;

            // System.out.println("mod[" +  part + "]org[" + org_part + "]");
            if (part.equals(org_part)) {
                if (!matched) {
                    m_s = s;
                    n_m_e = s;

                    if (n_m_e - n_m_s > 0 && n_m_s != -1) {
                        // System.out.println("n_m_s to n_m_e=" + n_m_s + "/" + n_m_e);
                        try {
                            String nomatch = mod.substring(n_m_s, n_m_e);
                            strlist.add(new ParmGenString(false, n_m_s, n_m_e, nomatch));
                        } catch (IndexOutOfBoundsException ex) {

                        }
                        n_m_s = -1;
                    }
                }
                matched = true;
                o_s++;
                if (o_s >= org_length) { // 全一致
                    m_e = e;
                    if (m_e - m_s > 0 && m_s != -1) {
                        // System.out.println("m_s to m_e=" + m_s + "/" + m_e);
                        try {
                            String match = mod.substring(m_s, m_e);
                            strlist.add(new ParmGenString(true, m_s, m_e, match));
                        } catch (IndexOutOfBoundsException ex) {

                        }
                        m_s = -1;
                    }
                    n_m_s = e;
                    orgmatchall = true;
                }
            } else {
                if (matched) {
                    n_m_s = s;
                    m_e = s;
                    if (m_e - m_s > 0 && m_s != -1) {
                        // System.out.println("m_s to m_e=" + m_s + "/" + m_e);
                        try {
                            String match = mod.substring(m_s, m_e);
                            strlist.add(new ParmGenString(true, m_s, m_e, match));
                        } catch (IndexOutOfBoundsException ex) {

                        }
                        m_s = -1;
                    }
                } else if (s == 0) {
                    n_m_s = s;
                }
                matched = false;
            }
        }

        if (m_s != -1) {
            m_e = mod_length;
            if (m_e > m_s) {
                try {
                    String match = mod.substring(m_s, m_e);
                    strlist.add(new ParmGenString(true, m_s, m_e, match));
                } catch (IndexOutOfBoundsException ex) {

                }
            }
            // System.out.println("m_s to m_e=" + m_s + "/" + m_e);
        } else if (n_m_s != -1) {
            n_m_e = mod_length;
            if (n_m_e > n_m_s) {
                try {
                    String nomatch = mod.substring(n_m_s, n_m_e);
                    strlist.add(new ParmGenString(false, n_m_s, n_m_e, nomatch));
                } catch (IndexOutOfBoundsException ex) {

                }
            }
            // System.out.println("n_m_s to n_m_e=" + n_m_s + "/" + n_m_e);
        }

        return strlist;
    }

    boolean isOrgMatchedAll() {
        return orgmatchall;
    }

    String replaceOrgMatchedValue(String rstr) {
        List<ParmGenString> slist = analyze();
        int rs = 0;
        int end = rstr.length();
        String nstr = "";
        String ogs = "";
        if (isOrgMatchedAll() && slist != null) {
            // matchvalにorginalが包含されている。
            for (ParmGenString pstr : slist) {
                int _s = pstr.getStartPos();
                int _e = pstr.getEndPos();
                int _l = _e - _s;
                // System.out.println("_s/_e/_l" + _s + "/" + _e + "/" + _l);
                if (pstr.isMatched()) {
                    int _re = rs + _l;
                    int re = _re > end ? end : _re;
                    ogs += pstr.getValue();
                    if (ogs.equals(org)) {
                        re = end;
                    }

                    if (re > rs && rs < end) {
                        nstr += rstr.substring(rs, re);
                        rs = re;
                    }
                } else {
                    nstr += pstr.getValue();
                }
            }
        } else {
            return null;
        }
        return nstr;
    }
}
