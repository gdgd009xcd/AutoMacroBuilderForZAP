package org.zaproxy.zap.extension.automacrobuilder.view;

import javax.swing.*;

@SuppressWarnings({"unchecked", "serial"})
public class CaridgeReturnLabel extends JLabel implements InterfaceCompoStyleName {
    private String styleName;
    public CaridgeReturnLabel(String styleName, String value){
        super(value);
        this.styleName = styleName;
    }

    @Override
    public void setStyleName(String name) {
        this.styleName = name;
    }

    @Override
    public String getStyleName() {
        return this.styleName;
    }
}
