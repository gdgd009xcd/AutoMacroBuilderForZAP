/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.awt.Dimension;
import java.awt.Frame;
import java.util.ArrayList;
import java.util.List;
import org.zaproxy.zap.extension.ascan.CustomScanDialog;
import org.zaproxy.zap.extension.ascan.CustomScanPanel;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;

/** @author daike */
@SuppressWarnings("serial")
public class CustomScanDialogForMacroBuilder
        extends org.zaproxy.zap.extension.ascan.CustomScanDialog {

    private ExtensionActiveScanWrapper extensionwrapper = null;
    
    public static final String[] STD_TAB_LABELS_REF = CustomScanDialog.STD_TAB_LABELS;

    public CustomScanDialogForMacroBuilder(
            ExtensionActiveScanWrapper ext,
            String[] tabLabels,
            List<CustomScanPanel> customPanels,
            Frame owner,
            Dimension dim) {
        super(ext, tabLabels, customPanels, owner, dim);
        this.extensionwrapper = ext;
    }

    /**
     * Since MacroBuilder does not require zap's user authentication, this method always sets the
     * user selection combo box to "".
     *
     * @param fieldLabel
     * @param choices
     * @param value
     */
    @Override
    public void setComboFields(String fieldLabel, List<String> choices, String value) {

        if (fieldLabel != null && fieldLabel.equals("ascan.custom.label.user")) {
            List<String> blanks = java.util.Arrays.asList(new String[] {""});
            super.setComboFields(fieldLabel, blanks, "");
        } else {
            super.setComboFields(fieldLabel, choices, value);
        }
    }
}
