package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class CustomTagConverter {
    public static class ConvertMap {
        char original;
        String encoded;
        ConvertMap(char original, String encoded) {
            this.original = original;
            this.encoded = encoded;
        }
    }

    private final ConvertMap[] convertMaps = {
            new ConvertMap('\n', "<%LF>"),
            new ConvertMap('\r', "<%CR>"),
            new ConvertMap('\t', "<%TAB>"),
            new ConvertMap(' ', "<%SP>"),
            new ConvertMap('/', "<%SL>"),
            new ConvertMap('\\', "<%BKSL>")
    };

    public int maxEncodedLength = 5;// String length of ConverMap.encoded
    public Map<Character, String> convOriginal2Encoded;
    public Map<String, Character> convEncoded2Original;

    public CustomTagConverter() {
        convOriginal2Encoded = new HashMap<>();
        convEncoded2Original = new HashMap<>();
        for(ConvertMap convertMap: convertMaps) {
            convOriginal2Encoded.put(convertMap.original, convertMap.encoded);
            convEncoded2Original.put(convertMap.encoded, convertMap.original);
        }
    }

    private static CustomTagConverter customStringConverterInstance = null;
    public static CustomTagConverter getCustomStringConverter() {
        if (customStringConverterInstance == null) {
            customStringConverterInstance = new CustomTagConverter();
        }
        return customStringConverterInstance;
    }



    public static String customEncode(String original) {
        if (original==null) {
            original = "";
        }
        return original.chars()
                .mapToObj(new DefaultMapCharWithCustomTagFunction())
                .collect(Collectors.joining());
    }

    public static String customEncode(String original, Map<Integer, Integer> counterMap, int originalOffset, int encodedOffset) {
        if (original==null) {
            original = "";
        }
        return original.chars()
                .mapToObj(new CounterMapCharWithCustomTagFunction(counterMap, originalOffset, encodedOffset))
                .collect(Collectors.joining());
    }

    public static String customDecode(String customEncoded) {
        if (customEncoded==null) {
            customEncoded = "";
        }
        return customEncoded.chars()
                .mapToObj(i -> String.valueOf((char)i))
                .collect(new DefaultDecodeCustomTagStringCollector());
    }

}
