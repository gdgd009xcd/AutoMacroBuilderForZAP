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

import static org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionAutoMacroBuilder.PREFIX;

import java.awt.Dimension;
import javax.swing.JMenuItem;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.automacrobuilder.PRequest;
import org.zaproxy.zap.extension.automacrobuilder.PRequestResponse;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceParams;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.mdepend.ClientDependMessageContainer;
import org.zaproxy.zap.extension.forceduser.ExtensionForcedUser;
import org.zaproxy.zap.model.Target;

/** @author gdgd009xcd */
@SuppressWarnings("serial")
public class PopUpItemActiveScan extends JMenuItem {

    private MacroBuilderUI mbui = null;
    private ExtensionActiveScanWrapper extension = null;
    private CustomScanDialogForMacroBuilder customScanDialog = null;
    private ExtensionHistory extHistory = null;
    private ExtensionForcedUser extForce = null;
    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    PopUpItemActiveScan(MacroBuilderUI mbui, ExtensionActiveScanWrapper extension) {

        super(Constant.messages.getString(PREFIX + ".popup.title.PopUpActiveScanForMacroBuilder"));
        this.extension = extension;
        this.mbui = mbui;

        addActionListener(
                ev -> {
                    PRequest newrequest = ZapUtil.getPRequestFromMacroRequest(this.mbui);
                    if (newrequest != null) {
                        ParmGenMacroTrace pmt = this.mbui.getParmGenMacroTrace();
                        int currentSelectedPos = this.mbui.getCurrentSelectedRequestIndex();
                        int subSequenceScanLimit = this.mbui.getSubSequenceScanLimit();
                        int lastStepNo =
                                pmt.getLastStepNo(currentSelectedPos, subSequenceScanLimit);
                        ParmGenMacroTraceParams targetStepNo =
                                new ParmGenMacroTraceParams(currentSelectedPos, lastStepNo);
                        this.extension.setTargetStepNo(targetStepNo);

                        PRequestResponse prr =
                                pmt.getRequestResponseCurrentList(currentSelectedPos);
                        ClientDependMessageContainer cdmcon = prr.getClientDependMessageContainer();
                        HistoryReference href =
                                cdmcon != null ? cdmcon.getClientDpendMessage() : null;
                        SiteNode sn = null;
                        if (href == null
                                || getExtensionHistory().getHistoryReference(href.getHistoryId())
                                        == null) {
                            // add RequestResponse to HistoryReference
                            HttpMessage htmess = addPRequestResponse2HistoryReference(prr);
                            if (htmess != null) {
                                // add htmess to siteTree Model
                                href = htmess.getHistoryRef();

                                sn = addHistoryReferenceAndMakeNode(href);

                                if (sn != null) {
                                    if (cdmcon == null) {
                                        cdmcon = new ClientDependMessageContainer(href);
                                        prr.setClientDependMessageContainer(cdmcon);
                                    } else {
                                        cdmcon.setClientDependMessage(href);
                                    }
                                }
                            }
                        } else {
                            sn = getSiteNode(href);
                        }

                        LOGGER4J.debug("sn:" + (sn == null ? "null" : "NO null"));

                        if (sn != null) {
                            // set forceUsermode off through API
                            this.extension.setTargetStepNo(targetStepNo);
                            showCustomScanDialog(sn);
                        }
                    }
                });
    }

    /**
     * Add specified paramter's request/response message to HistoryReference. Returns HttpMessage
     * Object which was added to HistoryReference.
     *
     * @param ppr
     * @return HttpMessage
     */
    private HttpMessage addPRequestResponse2HistoryReference(PRequestResponse ppr) {

        HttpMessage htmess = ZapUtil.getHttpMessage(ppr);
        htmess.setTimeSentMillis(System.currentTimeMillis());
        getExtensionHistory().addHistory(htmess, HistoryReference.TYPE_PROXIED);

        return htmess;
    }

    /**
     * Add a HistoryReference to siteTree, then returns SiteNode which was added to siteTree Model.
     *
     * @param href
     */
    private SiteNode addHistoryReferenceAndMakeNode(HistoryReference href) {

        SiteNode startNode = null;

        Model.getSingleton().getSession().getSiteTree().addPath(href);

        startNode = getSiteNode(href);

        return startNode;
    }

    /**
     * Get the SiteNode object to which the HistoryReference object belongs.
     *
     * @param historyReference
     * @return SiteNode
     */
    private SiteNode getSiteNode(HistoryReference historyReference) {
        if (historyReference == null) return null;
        SiteNode sn =
                historyReference.getSiteNode(); // internal cached SiteNode. may be already deleted?
        if (sn == null) {
            sn =
                    Model.getSingleton()
                            .getSession()
                            .getSiteTree()
                            .getSiteNode(historyReference.getHistoryId());
        }
        return sn;
    }

    public void showCustomScanDialog(HistoryReference historyReference) {
        showCustomScanDialog(getSiteNode(historyReference));
    }

    /**
     * Until zap ver 2.7, this method need to override.
     *
     * @param node
     */
    public void showCustomScanDialog(SiteNode node) {
        showCustomScanDialog(node != null ? new Target(node) : null);
    }

    /**
     * since ver 2.8 this method need to override
     *
     * @param target
     */
    public void showCustomScanDialog(Target target) {
        if (customScanDialog == null) {
            // Work out the tabs
            String[] tabs = CustomScanDialogForMacroBuilder.STD_TAB_LABELS_REF;

            customScanDialog =
                    new CustomScanDialogForMacroBuilder(
                            extension,
                            tabs,
                            null,
                            View.getSingleton().getMainFrame(),
                            new Dimension(700, 500));
        }
        if (customScanDialog.isVisible()) {
            customScanDialog.requestFocus();
            // Its behind you! Actually not needed no the window is alwaysOnTop, but keeping in case
            // we change that ;)
            customScanDialog.toFront();
            return;
        }
        if (target != null) {
            customScanDialog.init(target);
        } else {
            // Keep the previously selected target
            customScanDialog.init(null);
        }
        customScanDialog.setVisible(true);
    }

    /**
     * Get ExtensionHistory
     *
     * @return ExtensionHistory
     */
    private ExtensionHistory getExtensionHistory() {
        if (this.extHistory == null) {
            this.extHistory =
                    ((ExtensionHistory)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionHistory.NAME));
        }
        return this.extHistory;
    }

    private ExtensionForcedUser getExtensionForcedUser() {
        if (this.extForce == null) {
            this.extForce =
                    ((ExtensionForcedUser)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionForcedUser.NAME));
        }
        return this.extForce;
    }
}
