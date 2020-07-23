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

import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.*;
import org.zaproxy.zap.extension.automacrobuilder.generated.ParmGenRegex;

/** @author gdgd009xcd */
public class ParmGenUtil {

    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static String LFSIGN = "<!_DO_NOT_MODIFY_124kdsaoi2k_LF>\n";
    private static String LFSIGNEX = "\\<\\!_DO_NOT_MODIFY_124kdsaoi2k_LF\\>\\n";

    public static String LFinsert(String data) {
        StringBuffer sb = new StringBuffer();
        int mlen = 512;
        if (data == null) return null;
        int datalen = data.length();
        int multi = datalen / mlen;
        int remain = datalen % mlen;

        int end = datalen - remain;
        if (multi > 0) {
            for (int p = 0; p < end; p += mlen) {
                String line = data.substring(p, p + mlen);
                sb.append(line);
                if (!line.contains("\n")) {
                    sb.append(LFSIGN);
                }
            }
            if (end < datalen) {
                sb.append(data.substring(end, datalen));
            }
        } else {
            return data;
        }
        return sb.toString();
    }

    public static String LFremove(String data) {
        if (data == null) return null;
        return data.replaceAll(LFSIGNEX, "");
    }

    public static int parseMaxInt(String i) {

        int _i;
        try {
            _i = Integer.parseInt(i);
        } catch (Exception e) {
            _i = 0x7fffffff; // integer 最大値
        }

        return _i;
    }

    public static int parseMinInt(String i) {
        int _i;
        try {
            _i = Integer.parseInt(i);
        } catch (Exception e) {
            _i = 0; // integer 最小値
        }

        return _i;
    }

    public static String escapeRegexChars(String _d) {
        _d = _d.replaceAll("([\\+\\{\\}\\[\\]\\(\\)\\*\\.\\<\\>\\?\\^\\$])", "\\\\$1");
        return _d;
    }

    public static String getPathsRegex(String path) {
        int question = path.indexOf("?");
        int hash = path.indexOf("#");

        if (question >= 0) {
            String url = path.substring(0, question);
            String args = path.substring(question + 1);
            return "(" + escapeRegexChars(url) + "\\?" + getArgRegex(args) + ")";
        } else if (hash >= 0) {
            String url = path.substring(0, hash);
            String args = path.substring(hash + 1);
            return "(" + escapeRegexChars(url) + "#" + getArgRegex(args) + ")";
        }
        return "(" + escapeRegexChars(path) + ")";
    }

    public static ArrayList<String> getGroupRegexes(String r) {
        // (?:^|[^\\])(\([^?].*?\))
        ArrayList<String> glist = new ArrayList<String>();

        String greg = "(?:^|[^\\\\])(\\([^?].*?\\))"; // 後方参照グループ
        Pattern pattern = ParmGenUtil.Pattern_compile(greg);
        Matcher matcher = pattern.matcher(r);
        int gtotal = 0;
        while (matcher.find()) {
            int n = matcher.groupCount();
            for (int j = 1; j <= n; j++) {
                String matchval = matcher.group(j);
                glist.add(matchval);
            }
        }
        return glist;
    }

    public static String getArgRegex(String v) {
        int pos = 0;
        int nextpos;
        String arglist = "";

        while ((nextpos = v.indexOf("&", pos)) >= 0) {
            String param = v.substring(pos, nextpos);
            int equalpos = param.indexOf("=");
            if (equalpos >= 0) {
                String name = param.substring(0, equalpos);
                String value = param.substring(equalpos + 1);
                String vregex = ParmGenRegex.getParsedRegexRaw(value, "*");
                String namevalue = escapeRegexChars(name) + "=" + vregex;
                arglist += namevalue + "&";
            } else {
                arglist += escapeRegexChars(param) + "&";
            }
            pos = nextpos + 1;
        }
        if (pos > 0) {
            arglist += escapeRegexChars(v.substring(pos));
        } else {
            arglist = escapeRegexChars(v);
        }
        return arglist;
    }

    // target文字列中の検索正規表現regexのマッチカウント
    public static int getRegexMatchpos(String regex, String target) {
        Pattern pattern = ParmGenUtil.Pattern_compile(regex);
        Matcher matcher = pattern.matcher(target);
        int mcnt = 0;
        while (matcher.find()) {
            mcnt++;
        }
        return mcnt;
    }

    public static ArrayList<String> getRegexMatchGroups(String regex, String searchTarget) {
        Pattern pattern = ParmGenUtil.Pattern_compile(regex);
        Matcher matcher = pattern.matcher(searchTarget);
        int mcnt = 0;
        ArrayList<String> groups = new ArrayList<String>();
        while (matcher.find()) {
            int gcnt = matcher.groupCount();

            for (int i = 1; i <= gcnt; i++) {
                groups.add(matcher.group(i));
            }
        }
        return groups;
    }

    enum CharMODE {
        NUMBER,
        ALPHALOWER,
        ALPHAUPPER,
        OTHER,
        SPACE,
        DEFAULT
    };

    public static boolean isTokenValue(String tkn) {
        if (tkn == null || tkn.length() <= 16) return false;

        CharMODE current = CharMODE.DEFAULT;
        int ncnt = 0;
        int lowercnt = 0;
        int uppercnt = 0;
        char[] charArray = tkn.toCharArray();
        for (char ch : charArray) {
            switch (ch) {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9': // 数値
                    switch (current) {
                        case NUMBER:
                            break;
                        default:
                            ncnt++;
                            break;
                    }
                    current = CharMODE.NUMBER;
                    break;
                case 'a':
                case 'b':
                case 'c':
                case 'd':
                case 'e':
                case 'f':
                case 'g':
                case 'h':
                case 'i':
                case 'j':
                case 'k':
                case 'l':
                case 'm':
                case 'n':
                case 'o':
                case 'p':
                case 'q':
                case 'r':
                case 's':
                case 't':
                case 'u':
                case 'v':
                case 'w':
                case 'x':
                case 'y':
                case 'z':
                    switch (current) {
                        case ALPHALOWER:
                            break;
                        default:
                            lowercnt++;
                            break;
                    }
                    current = CharMODE.ALPHALOWER;
                    break;
                case 'A':
                case 'B':
                case 'C':
                case 'D':
                case 'E':
                case 'F':
                case 'G':
                case 'H':
                case 'I':
                case 'J':
                case 'K':
                case 'L':
                case 'M':
                case 'N':
                case 'O':
                case 'P':
                case 'Q':
                case 'R':
                case 'S':
                case 'T':
                case 'U':
                case 'V':
                case 'W':
                case 'X':
                case 'Y':
                case 'Z':
                    switch (current) {
                        case ALPHAUPPER:
                            break;
                        default:
                            uppercnt++;
                            break;
                    }
                    current = CharMODE.ALPHAUPPER;
                    break;
                case ' ':
                case '\t':
                case '\r':
                case '\n':
                    current = CharMODE.SPACE;
                    break;
                default:
                    current = CharMODE.OTHER;
                    break;
            }
            if (current == CharMODE.SPACE) return false;
        }
        // System.out.println("number/lower/upper=" + ncnt + "/" +lowercnt + "/" + uppercnt);
        if (ncnt >= 4 || (lowercnt >= 4 && uppercnt >= 4)) return true;
        return false;
    }

    public static Pattern Pattern_compile(String regex) {
        return Pattern_compile(regex, 0);
    }

    public static Pattern Pattern_compile(String regex, int opt) {
        return Pattern.compile(regex, opt | Pattern.MULTILINE);
    }

    /**
     * deep copy byte[]
     *
     * @param srcbin
     * @return byte[] byte array or null
     */
    public static byte[] copyBytes(byte[] srcbin) {
        if (srcbin != null && srcbin.length > 0) {
            byte[] nbin = new byte[srcbin.length];
            System.arraycopy(srcbin, 0, nbin, 0, srcbin.length);
            return nbin;
        }
        return null;
    }
    /**
     * deep copy String[]
     *
     * @param sarray
     * @return String[] or null
     */
    public static String[] copyStringArray(String[] sarray) {
        if (sarray != null && sarray.length > 0) {
            String[] narray = new String[sarray.length];
            System.arraycopy(sarray, 0, narray, 0, sarray.length);
            return narray;
        }
        return null;
    }

    /**
     * deepcopy ArrayList<String[]>
     *
     * @param slist
     * @return ArrayList<String[]> or null
     */
    public static ArrayList<String[]> copyStringArrayList(ArrayList<String[]> slist) {
        if (slist != null) {
            ArrayList<String[]> nlist = new ArrayList<>();
            for (String[] sarray : slist) {
                String[] narray = copyStringArray(sarray);
                if (narray != null) {
                    nlist.add(narray);
                }
            }
            return nlist;
        }
        return null;
    }

    /**
     * from ZapProxy's constant.java..
     *
     * @param targetFile
     * @param sourceFilePath
     * @param fallbackResource
     * @throws IOException
     */
    public static void copyFileToHome(
            Path targetFile, String sourceFilePath, String fallbackResource) throws IOException {
        Path defaultConfig =
                Paths.get(
                        System.getProperty("user.home"),
                        ".ZAP",
                        sourceFilePath); // ~user/.ZAP/sourceFilePath
        Files.createDirectories(targetFile.getParent());
        if (Files.exists(defaultConfig)) {
            Files.copy(defaultConfig, targetFile, StandardCopyOption.REPLACE_EXISTING);
        } else {
            try (InputStream is = ParmGenUtil.class.getResourceAsStream(fallbackResource)) {
                if (is == null) {
                    throw new IOException("Bundled resource not found: " + fallbackResource);
                }

                Files.copy(is, targetFile, StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    /**
     * @param filename
     * @return Optional<String> or Optional.empty().
     */
    public static Optional<String> getExtensionByStringHandling(String filename) {
        // 1) ofNullable() : if filename is not null, then filter method is called. otherwise return
        // Optional.empty().
        // 2) .filter(): if f.contains(".") is true, then map method called. otherwise return
        // Optional.empty().
        // 3) .map():  if f is not null then call f.substring == prefix return.
        return Optional.ofNullable(filename)
                .filter(f -> f.contains("."))
                .map(f -> f.substring(filename.lastIndexOf(".") + 1));
    }

    public static String[] MIMEBINTYPES = {
        "image", "application", "audio", "font", "model", "video"
    };

    /**
     * contenttype is binary mime data(image..etc.) or not
     *
     * @param contenttype
     * @return
     */
    public static boolean isBinaryMimeContent(String contenttype) {
        String[] str = contenttype.split("/");
        if (str.length > 1) {
            String type = str[0].toLowerCase();
            String subtype = str[1].toLowerCase();

            for (int i = 0; i < MIMEBINTYPES.length; i++) {
                if (type.equals(MIMEBINTYPES[i])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * nullable String equals
     *
     * @param a
     * @param b
     * @return
     */
    public static boolean nullableStringEquals(String a, String b) {
        if (a == null) {
            a = "";
        }
        if (b == null) {
            b = "";
        }
        return a.equals(b);
    }

    /**
     * get Status of String from ImageIcon
     *
     * @param icon
     * @return
     */
    public static String ImageIconLoadStatus(ImageIcon icon) {
        if (icon == null) return "NULL";
        String mess = "";
        switch (icon.getImageLoadStatus()) {
            case MediaTracker.ABORTED:
                mess = "ABORTED";
                break;
            case MediaTracker.COMPLETE:
                mess = "COMPLETE";
                break;
            case MediaTracker.ERRORED:
                mess = "ERRORED";
                break;
            case MediaTracker.LOADING:
                mess = "LOADING";
                break;
            default:
                mess = "UNKNOWN";
                break;
        }
        return mess;
    }
}
