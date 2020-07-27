/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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

import java.util.List;
import java.util.stream.Collectors;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.generated.LangSelectDialog;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.mdepend.ClientDependMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHistoryReferenceContainer;

public class PopupMenuAdd2MacroBuilder extends PopupMenuItemHistoryReferenceContainer
        implements InterfaceLangOKNG {

    private static final long serialVersionUID = 1L;
    private LangSelectDialog langdialog = null;
    private ParmGenMacroTrace pmt = null;
    private MacroBuilderUI mbui = null;
    private List<PRequestResponse> listprr = null;
    private List<HistoryReference> hrefs = null;

    /** @param label */
    public PopupMenuAdd2MacroBuilder(MacroBuilderUI mbui, ParmGenMacroTrace pmt, String label) {
        super(label, true);
        this.pmt = pmt;
        this.mbui = mbui;
        langdialog = new LangSelectDialog(null, this, Encode.ISO_8859_1, true);
    }

    @Override
    public void performAction(HistoryReference href) {}

    @Override
    protected void performHistoryReferenceActions(List<HistoryReference> hrefs) {
        this.hrefs = hrefs;
        this.hrefs.stream()
                .forEach(
                        href -> {
                            System.out.println("" + href.toString());
                        });

        this.listprr =
                hrefs.stream()
                        .map(
                                href ->
                                        new PRequestResponse(
                                                new ClientDependMessageContainer(href), null))
                        .collect(Collectors.toList());

        if (pmt.getRlistCount() <= 0) {
            List<PResponse> listres =
                    listprr.stream().map(prr -> prr.response).collect(Collectors.toList());
            Encode lang = Encode.analyzeCharset(listres);
            langdialog.setLang(lang);
            langdialog.setVisible(true);
        } else {
            LangOK();
        }
    }

    @Override
    public void LangOK() {
        // selected encode applied to PRequestResponses.
        this.listprr =
                this.hrefs.stream()
                        .map(
                                href ->
                                        new PRequestResponse(
                                                new ClientDependMessageContainer(href),
                                                ParmVars.enc))
                        .collect(Collectors.toList());
        mbui.addNewRequests(this.listprr);
        langdialog.setVisible(false);
    }

    @Override
    public void LangCANCEL() {
        langdialog.setVisible(false);
    }
}
