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
package org.zaproxy.zap.extension.automacrobuilder;

import java.awt.Component;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.table.TableCellRenderer;

/** @author gdgd009xcd */
@SuppressWarnings("serial")
public class LineWrapRenderer extends JTextArea implements TableCellRenderer {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public LineWrapRenderer() {
        super();
        setLineWrap(true);
    }

    @Override
    public Component getTableCellRendererComponent(
            JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        if (isSelected) {
            setForeground(table.getSelectionForeground());
            setBackground(table.getSelectionBackground());
        } else {
            setForeground(table.getForeground());
            setBackground(table.getBackground());
        }
        setText((value == null) ? "" : value.toString());

        // Set the component width to match the width of its table cell
        // and make the height arbitrarily large to accomodate all the contents
        setSize(table.getColumnModel().getColumn(column).getWidth(), Short.MAX_VALUE);

        // Now get the JTextArea's fitted height for the given width
        int rowHeight = this.getPreferredSize().height;

        // Get the current table row height
        int actualRowHeight = table.getRowHeight(row);

        // Set table row height to fitted height.
        // Important to check if this has been done already
        // to prevent a never-ending loop.
        if (rowHeight != actualRowHeight) {
            LOGGER4J.debug(
                    "setRowHeight: rowHeight" + rowHeight + "!=actuaRowHeight:" + actualRowHeight);
            table.setRowHeight(row, rowHeight);
        }
        return this;
    }
}
