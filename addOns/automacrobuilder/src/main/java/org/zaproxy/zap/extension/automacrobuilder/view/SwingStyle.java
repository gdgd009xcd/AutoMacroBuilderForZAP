package org.zaproxy.zap.extension.automacrobuilder.view;

import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Style;
import javax.swing.text.StyleContext;
import javax.swing.text.StyledDocument;
import java.util.Enumeration;

public class SwingStyle {

    public static String STYLE_NAME = "###UNIQUE_SWING_STYLE###";

    private StyleContext styleContext = null;

    SwingStyle() {
        styleContext =  new StyleContext();
        styleContext.addStyle(STYLE_NAME, styleContext.getStyle((StyleContext.DEFAULT_STYLE)));
    }

    public StyleContext getStyleContext() {
        return styleContext;
    }

    public StyledDocument createStyledDocument() {
        return new DefaultStyledDocument(styleContext);
    }

    public static Style getDefaultStyle(StyledDocument doc) {
        Style style = doc.getStyle(STYLE_NAME);
        if (style == null) {
            return doc.getStyle(StyleContext.DEFAULT_STYLE);
        }
        return style;
    }

    /**
     * clear All [character] attributes and set attributes as default.
     * existing [character] attributes is removed.
     * but remain other component attributes such as image component.
     * @param doc StyledDocument
     */
    public static void clearAllCharacterAttributes(StyledDocument doc) {
        Style defaultStyle = getDefaultStyle(doc);
        // replace "true" means overwrite char attributes with defaultStyle. existing character attributes is deleted.
        // but remain other component attributes such as image component.
        doc.setCharacterAttributes(0, doc.getLength(), defaultStyle, true);
    }

}
