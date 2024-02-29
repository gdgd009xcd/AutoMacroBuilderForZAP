package org.zaproxy.zap.extension.automacrobuilder.view;

import org.zaproxy.zap.extension.automacrobuilder.view.InterfacePlaceHolderStyle;

public class PlaceHolderStyle implements InterfacePlaceHolderStyle {
    private String styleName;
    private int pos;

    public PlaceHolderStyle(int pos, String styleName) {
        this.pos = pos;
        this.styleName = styleName;
    }

    @Override
    public int getPos() {
        return this.pos;
    }

    @Override
    public String getStyleName() {
        return this.styleName;
    }
}
