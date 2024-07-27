package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.util.Map;
import java.util.function.IntFunction;

public class DefaultMapCharWithCustomTagFunction implements IntFunction<String> {
    final Map<Character, String> converter = CustomTagConverter.getCustomStringConverter().convOriginal2Encoded;
    @Override
    public String apply(int i) {
        char c = (char)i;
        String value = String.valueOf(c);
        String encoded = getConverter().get(c);
        if (encoded != null) {
            value = encoded;
        }
        return value;
    }

    protected Map<Character, String> getConverter() {
        return converter;
    }
}
