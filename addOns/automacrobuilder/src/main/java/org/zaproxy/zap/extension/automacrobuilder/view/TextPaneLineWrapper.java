/*
 * Copyright 2024 gdgd009xcd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.automacrobuilder.view;

import javax.swing.text.*;

/**
 * Usage: jEditorPane1.setEditorKit(new TextPaneLineWrapper(newDocument));
 *
 * <p>jScrollPane's set HorizontalScrollBarPolycy ; Never set VerticalScrollBarPolycy; AS_NEEDED.
 * <p>long word line wrapper.
 * <p>setEditorKit destroy existing Document and call EditoKit.createDocument for setting it.
 * so you must specify custom document when create this EditorKit instance.</p>
 *
 */

@SuppressWarnings("serial")
public class TextPaneLineWrapper extends StyledEditorKit {
    ViewFactory defaultFactory = new WrapColumnFactory();

    Document doc;
    public TextPaneLineWrapper(Document doc) {
        this.doc = doc;
    }

    @Override
    public ViewFactory getViewFactory() {
        return defaultFactory;
    }
    @Override
    public Document createDefaultDocument() {
        return this.doc;
    }
}

class WrapColumnFactory implements ViewFactory {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public View create(Element elem) {
        String kind = elem.getName();
        LOGGER4J.debug("elem:" + kind);
        if (kind != null) {
            if (kind.equals(AbstractDocument.ContentElementName)) {
                return new WrapLabelView(elem);
            } else if (kind.equals(AbstractDocument.ParagraphElementName)) {
                return new MyParagraphView(elem);
            } else if (kind.equals(AbstractDocument.SectionElementName)) {
                return new BoxView(elem, View.Y_AXIS);
            } else if (kind.equals(StyleConstants.ComponentElementName)) {
                return new ComponentView(elem);
            } else if (kind.equals(StyleConstants.IconElementName)) {
                return new IconView(elem);
            }
        }

        // default to text display
        return new LabelView(elem);
    }
}

class WrapLabelView extends LabelView {
    public WrapLabelView(Element elem) {
        super(elem);
    }

    public static float MAX_y = 0;

    @Override
    public float getMinimumSpan(int axis) {

        switch (axis) {
            case View.X_AXIS:
                return 0;
            case View.Y_AXIS:
                return 0; // super.getMinimumSpan(axis);
            default:
                throw new IllegalArgumentException("Invalid axis: " + axis);
        }
    }
}

class MyParagraphView extends ParagraphView {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public MyParagraphView(Element elem) {
        super(elem);
    }

    protected void layout(int width, int height) {
        long start = System.currentTimeMillis();
        if (width < Integer.MAX_VALUE) {
            super.layout(width, height);
        }
        long end = System.currentTimeMillis();

        LOGGER4J.debug("w=" + width + " h=" + height + " time=" + (end - start));
    }

    @Override
    public float getMinimumSpan(int axis) {
        switch (axis) {
            case View.X_AXIS:
                return 0;
            case View.Y_AXIS:
                return super.getMinimumSpan(axis);
            default:
                throw new IllegalArgumentException("Invalid axis: " + axis);
        }
    }
}
