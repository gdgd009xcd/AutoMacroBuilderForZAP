package org.zaproxy.zap.extension.automacrobuilder.view;

import org.zaproxy.zap.extension.automacrobuilder.CastUtils;

import javax.swing.text.*;
import java.awt.*;

@SuppressWarnings({"unchecked", "serial"})
public class ManagedStyledDocument extends DefaultStyledDocument {
    private final static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    public ManagedStyledDocument(StyleContext styleContext) {
        super(styleContext);
    }
    /**
     * set Character attributes except component positions.
     * @param startPos
     * @param length
     * @param style
     * @param replace
     */
    public void setCharacterAttributeExceptComponents(int startPos, int length, Style style, boolean replace) {
        int exStartPos = startPos;
        int exEndPos = startPos + length;
        int curStart = exStartPos;
        int curEnd = -1;
        for(int pos = exStartPos; pos < exEndPos; pos++) {
            Element elm = this.getCharacterElement(pos);
            if (elm != null) {
                AttributeSet attrSet = elm.getAttributes();
                if (attrSet != null) {
                    String styleName = "";
                    // I can get StyleName and Component from the AttributeSet at last!
                    Object name = attrSet.getAttribute(AttributeSet.NameAttribute);
                    if (name != null) {
                        // character's styleName is overwrited each calling setCharacterAttributes.
                        // so below styleName is changed from original.
                        styleName = CastUtils.castToType(name);
                    }
                    Component compo = StyleConstants.getComponent(attrSet);
                    if (compo != null) {
                        if (compo instanceof InterfaceCompoStyleName) {
                            InterfaceCompoStyleName compoStyle = (InterfaceCompoStyleName) compo;
                            styleName = compoStyle.getStyleName();
                        }
                        curEnd = pos;
                        int len = curEnd - curStart;
                        if (len > 0) {
                            this.setCharacterAttributes(curStart, len, style, replace);
                            LOGGER4J.debug("curStart,curEnd:" + curStart + "," + curEnd + " style:[" + style.getName() + "]");
                        }
                        LOGGER4J.debug("pos=" + pos + " except component name[" + styleName + "]");
                        curStart = curEnd + 1;
                    }
                }
            }
        }
        if (curStart < exEndPos) {
            curEnd = exEndPos;
            int len = curEnd - curStart;
            this.setCharacterAttributes(curStart, len, style, replace);
            LOGGER4J.debug("curStart,curEnd:" + curStart + "," + curEnd + " style:[" + style.getName() + "]");
        }
    }
}
