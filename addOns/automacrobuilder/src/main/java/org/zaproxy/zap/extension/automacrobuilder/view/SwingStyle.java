package org.zaproxy.zap.extension.automacrobuilder.view;

import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.Style;
import javax.swing.text.StyleContext;
import javax.swing.text.StyledDocument;

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
        return doc.getStyle(STYLE_NAME);
    }

}
