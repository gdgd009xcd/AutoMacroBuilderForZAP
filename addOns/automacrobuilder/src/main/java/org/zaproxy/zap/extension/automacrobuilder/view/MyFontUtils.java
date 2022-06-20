package org.zaproxy.zap.extension.automacrobuilder.view;

import java.awt.*;
import javax.swing.*;

public class MyFontUtils {
    public static float DEFAULT_FONT_SIZE = 12;

    public static Font currentLookAndFeelFont = null;

    private static float getLookAndFeelFontScale() {
        if (currentLookAndFeelFont == null) {
            currentLookAndFeelFont = (Font) UIManager.getLookAndFeelDefaults().get("defaultFont");
        }
        if (currentLookAndFeelFont != null) {
            return currentLookAndFeelFont.getSize2D();
        }
        return DEFAULT_FONT_SIZE;
    }

    public static float getScale() {
        return getLookAndFeelFontScale() / DEFAULT_FONT_SIZE;
    }

    public static ImageIcon getScaledIcon(ImageIcon icon) {
        if (icon == null || getScale() == 1) {
            // don't need to scale
            return icon;
        }
        return new ImageIcon(
                (icon)
                        .getImage()
                        .getScaledInstance(
                                (int) (icon.getIconWidth() * getScale()),
                                (int) (icon.getIconHeight() * getScale()),
                                Image.SCALE_SMOOTH));
    }
}
