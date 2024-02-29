package org.zaproxy.zap.extension.automacrobuilder;

import java.util.stream.IntStream;

import static java.util.stream.Collectors.joining;

public class PrintableString {

    private String nonPrintableString = null;

    public PrintableString(String nonPrintableString) {
        this.nonPrintableString = nonPrintableString;
    }

    public String convert(int len) {
        return convert(this.nonPrintableString, len);
    }

    public String convert(String original, int len) {
        this.nonPrintableString = original;

        if (original == null || original.isEmpty()) {
            return "";
        } else if (len > 0 && len < original.length()) {
            int divideLen = len / 2;
            int reminderlen = len % 2;
            int originalLen = original.length();
            original = original.substring(0, divideLen + reminderlen) + "..." + original.substring(originalLen - divideLen, originalLen);
        }

        String convertedString = "";
        try (IntStream istream = original.chars()) { // after executed, then this resource automatically be freed.

            convertedString = istream.mapToObj(ci -> {
                String value = "";
                if (ci <= 0x001f || ci == 0x007f || (ci >= 0x0080)) {
                    try {
                        value = String.format("%%%02x", ci);
                    } catch (Exception e) {
                    }
                } else {
                    value = String.valueOf((char) ci);
                }
                return value;
            }).collect(joining());
        }

        return convertedString;
    }
}
