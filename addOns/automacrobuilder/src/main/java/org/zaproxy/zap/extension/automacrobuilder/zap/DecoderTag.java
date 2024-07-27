package org.zaproxy.zap.extension.automacrobuilder.zap;

import org.zaproxy.zap.extension.automacrobuilder.Encode;
import org.zaproxy.zap.extension.automacrobuilder.StartEndPosition;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DecoderTag {
    private static final String SECTION_SIGN = "§";
    private static final String PILCROW_MARK = "¶";

    public static final String DECODE_PREFIX_URL_STRING = SECTION_SIGN + "U" + PILCROW_MARK;
    public static final String DECODE_SUFFIX_URL_STRING = PILCROW_MARK + "U" + SECTION_SIGN;
    public static final String DECODE_PREFIX_BASE64_STRING = SECTION_SIGN + "B" + PILCROW_MARK;
    public static final String DECODE_SUFFIX_BASE64_STRING = PILCROW_MARK + "B" + SECTION_SIGN;
    private static final String DECODEREGEX = "((?:§[BU]¶)+)((?:.|[\\r\\n\\t ])*?)(?<!¶[BU]§)((?:¶[BU]§)+)";
    //%C2%A7 U %C2%B6 %C2%A7 B %C2%B6 %C2%A7 U %C2%B6
    //%C2%B6 U %C2%A7 %C2%B6 B %C2%A7 %C2%B6 U %C2%A7
    private static final String ENCODEDREGEX = "((?:%C2%A7[BU]%C2%B6)+)((?:.|[\\r\\n\\t ])*?)(?<!%C2%B6[BU]%C2%A7)((?:%C2%B6[BU]%C2%A7)+)";
    private static final String DECODE_REMOVE_REGEX = "(§[BU]¶)|(¶[BU]§)";
    private static final String ENCODED_REMOVE_REGEX = "(%C2%A7[BU]%C2%B6)|(%C2%B6[BU]%C2%A7)";
    private static Pattern pattern = Pattern.compile(DECODEREGEX, Pattern.MULTILINE);
    private static Pattern UrlPattern = Pattern.compile(ENCODEDREGEX, Pattern.MULTILINE);

    public static List<StartEndPosition> getDecodeTagList(String value) {
        Matcher m = pattern.matcher(value);
        List<StartEndPosition> results = new ArrayList<>();;
        while (m.find()) {
            int gcount = m.groupCount();
            if (gcount == 3) {
                results.add(getStartEndPositionFromMatcherGroup(m, 1));
                results.add(getStartEndPositionFromMatcherGroup(m, 3));
            }
        }
        return results;
    }

    public static List<StartEndPosition> getDecodedStringList(String value) {
        Matcher m = pattern.matcher(value);
        List<StartEndPosition> results = new ArrayList<>();;
        while (m.find()) {
            int gcount = m.groupCount();
            if (gcount == 3) {
                results.add(getStartEndPositionFromMatcherGroup(m, 2));
            }
        }
        return results;
    }

    public static List<StartEndPosition> getUrledDecodedStringList(String value) {
        Matcher m = UrlPattern.matcher(value);
        List<StartEndPosition> results = new ArrayList<>();
        while(m.find()) {
            int gcount = m.groupCount();
            if (gcount == 3) {
                results.add(getStartEndPositionFromMatcherGroup(m, 0));
            }
        }
        return results;
    }

    /**
     * whether is value consist of valid CustomEncoded value
     * @param value
     * @return true - value is valid CustomEncoded value | false - not valid value
     */
    public static boolean isDecodedTaggedString(String value) {
        Matcher m = pattern.matcher(value);
        boolean totalResult = false;
        while (m.find()) {
            int gcount = m.groupCount();
            if (gcount != 3) {
                return false;
            } else {
                String prefixTag = m.group(1);
                String content = m.group(2);
                String suffixTag = m.group(3);
                if (prefixTag.length() != suffixTag.length()) {
                    return false;
                } else if (prefixTag.length() % 3 != 0) {
                    return false;
                } else {
                    int maxTagLabelIndex = prefixTag.length() - 2;
                    for (int i = 1, j = maxTagLabelIndex; i <= maxTagLabelIndex; i += 3, j -= 3) {
                        if (!prefixTag.substring(i, i + 1).equals(suffixTag.substring(j, j + 1))) {
                            return false;
                        }
                    }
                    totalResult = true;
                }
            }
        }
        return totalResult;
    }

    public static String getOriginalEncodedString(String value, Encode enc) {
        Matcher m = pattern.matcher(value);
        StringBuffer resultEncodedString =  new StringBuffer();
        int start = 0;
        Deque<String> stacker = new ArrayDeque<>();
        while (m.find()) {
            int gcount = m.groupCount();
            boolean failed = false;
            String content = "";
            stacker.clear();
            if (gcount == 3) {
                String prefixTag = m.group(1);
                content = m.group(2);
                String suffixTag = m.group(3);
                if (prefixTag.length() != suffixTag.length()) {
                    failed = true;
                } else if (prefixTag.length() % 3 != 0) {
                    failed = true;
                } else {

                    int maxTagLabelIndex = prefixTag.length() - 2;

                    for (int i = 1, j = maxTagLabelIndex; i <= maxTagLabelIndex; i += 3, j -= 3) {
                        if (!prefixTag.substring(i, i + 1).equals(suffixTag.substring(j, j + 1))) {
                            failed = true;
                            break;
                        } else {
                            stacker.push(prefixTag.substring(i, i + 1));
                        }
                    }
                }
            } else {
                failed = true;
            }
            if (failed) {
                resultEncodedString.append(value.substring(start, m.end()));
            } else {
                resultEncodedString.append(value.substring(start, m.start()));
                String encodeCommand;
                while((encodeCommand = stacker.pollFirst())!= null) {
                    switch(encodeCommand) {
                        case "U":
                            content = ZapUtil.encodeURL(content, enc);
                            break;
                        case "B":
                            content = ZapUtil.encodeBase64(content, enc);
                            break;
                    }
                }
                resultEncodedString.append(content);
            }
            start = m.end();
        }
        if (start < value.length()) {
            resultEncodedString.append(value.substring(start, value.length()));
        }
        return resultEncodedString.toString();
    }

    public static StartEndPosition getStartEndPositionFromMatcherGroup(Matcher m, int i) {
        int gStart = m.start(i);
        int gEnd = m.end(i);
        String groupString = m.group(i);
        return new StartEndPosition(gStart, gEnd, groupString);
    }

    public static String removeDecodeTag(String value) {
        if (value != null) {
            return value.replaceAll(DECODE_REMOVE_REGEX, "");
        }
        return null;
    }

    /**
     * encode CustomTag in customDecodedString argument and calculate encodeMap
     * @param customDecodedString
     * @param encodeMap
     * @return
     */
    public static String encodeCustomTagWithEncodeMap(String customDecodedString, Map<Integer, Integer> encodeMap) {

        List<StartEndPosition> tagList = getDecodedStringList(customDecodedString);
        int originalOffset = 0;
        int encodedOffset = 0;
        int lastEnd = 0;
        int decodedLength = customDecodedString.length();
        StringBuffer encodedBuffer = new StringBuffer();
        for(StartEndPosition position: tagList) {

            originalOffset = position.start;
            if (lastEnd < position.start) {
                for(int pos = lastEnd; pos < position.start; pos++) {
                    if (encodeMap.get(pos) != null) {
                        encodeMap.put(pos, pos + encodedOffset);
                    }
                }
                encodedBuffer.append(customDecodedString.substring(lastEnd, position.start));
            }
            String originalString = customDecodedString.substring(position.start, position.end);

            String encodedString = CustomTagConverter.customEncode(originalString, encodeMap, originalOffset, encodedOffset);
            encodedOffset += encodedString.length() - originalString.length();
            encodedBuffer.append(encodedString);
            lastEnd = position.end;

        }

        if (lastEnd < decodedLength) {
            for(int pos = lastEnd; pos < decodedLength; pos++) {
                if (encodeMap.get(pos) != null) {
                    encodeMap.put(pos, pos + encodedOffset);
                }
            }
            encodedBuffer.append(customDecodedString.substring(lastEnd));
        }

        return encodedBuffer.toString();
    }
}
