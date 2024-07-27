package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.util.HashMap;
import java.util.Map;

public class CounterMapCharWithCustomTagFunction extends DefaultMapCharWithCustomTagFunction {
    private Map<Integer, Integer> counterMap;
    private int originalCounter = 0;
    private int encodedCounter = 0;


    public CounterMapCharWithCustomTagFunction(Map<Integer, Integer> counterMap, int originalOffset, int encodedOffset) {
        init(counterMap, originalOffset, encodedOffset);
    }

    private void init(Map<Integer, Integer> encodeMap, int originalOffset, int encodedOffset) {
        this.counterMap = encodeMap;

        if (this.counterMap == null) {
            this.counterMap = new HashMap<>();
        }
        this.originalCounter = originalOffset;
        this.encodedCounter = originalOffset + encodedOffset;
        if (this.counterMap.get(this.originalCounter) != null) {
            this.counterMap.put(this.originalCounter, this.encodedCounter);
        }
    }

    @Override
    public String apply(int i) {
        char c = (char)i;
        String value = String.valueOf(c);
        String encoded = getConverter().get(c);
        originalCounter++;
        if (encoded != null) {
            value = encoded;
        }
        encodedCounter += value.length();
        if (this.counterMap.get(originalCounter) != null) {
            this.counterMap.put(originalCounter, encodedCounter);
        }
        return value;
    }
}
