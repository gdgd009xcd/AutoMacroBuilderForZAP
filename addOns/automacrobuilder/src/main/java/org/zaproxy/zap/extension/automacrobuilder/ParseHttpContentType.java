package org.zaproxy.zap.extension.automacrobuilder;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ParseHttpContentType {
    private Pattern regexPattern =
            Pattern.compile(
                    "^[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Tt][Yy][Pp][Ee]:[ \\t]*([^/\\r\\n \\t]+\\/[^/\\r\\n \\t;]+)[; \\t]+?.*?(?:[Cc][Hh][Aa][Rr][Ss][Ee][Tt])+[ \\t]*=[ \\t]*?(([^ \\t\\n\\x0B\\f\\r;]*))[; \\t]*.*$",
                    Pattern.MULTILINE);
    private String mediaType;
    private String charSetName;
    private boolean detected;
    private boolean isResponse;

    public ParseHttpContentType(String httpmessage) {
        parse(httpmessage);
    }

    public boolean parse(String httpmessage) {
        mediaType = "";
        charSetName = "";
        detected = false;
        isResponse = false;
        if (httpmessage != null && !httpmessage.isEmpty()) {
            int crlfSeparatorIndex = httpmessage.indexOf("\r\n\r\n");
            if (crlfSeparatorIndex != -1) {
                String httpHeaders = httpmessage.substring(0, crlfSeparatorIndex);
                if (!httpHeaders.isEmpty()) {
                    if (httpHeaders.toUpperCase().startsWith("HTTP/")) {
                        isResponse = true;
                    }
                    Matcher m = regexPattern.matcher(httpHeaders);
                    if (m.find()) {
                        int groupcount = m.groupCount();
                        if (groupcount >= 1) {
                            detected = true;
                            mediaType = m.group(1);
                            charSetName = m.group(2);
                            if (mediaType.toUpperCase().equals("APPLICATION/JSON")) {
                                charSetName = "UTF-8";
                            }
                        }
                    }
                }
            }
        }
        return detected;
    }

    public boolean hasContentTypeHeader() {
        return detected;
    }

    public boolean isResponse() {
        return isResponse;
    }

    public String getMediaType() {
        return mediaType;
    }

    public String getCharSetName() {
        return charSetName;
    }
}
