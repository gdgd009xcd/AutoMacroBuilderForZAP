package org.zaproxy.zap.extension.automacrobuilder;

public class StartEndPosition {
    public int start;
    public int end;
    public String styleName = null;
    public String value = null;
    public StartEndPosition(int start, int end) {
        this.start = start;
        this.end = end;
    }
    public StartEndPosition(int start, int end, String value) {
        this.start = start;
        this.end = end;
        this.value = value;
    }
}
