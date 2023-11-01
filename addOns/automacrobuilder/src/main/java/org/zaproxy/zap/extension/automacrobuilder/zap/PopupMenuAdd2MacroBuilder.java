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

import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.generated.LangSelectDialog;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.mdepend.ClientDependMessageContainer;
import org.zaproxy.zap.model.StructuralNode;
import org.zaproxy.zap.model.StructuralSiteNode;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.view.popup.PopupMenuItemSiteNodeContainer;

import javax.swing.*;

public class PopupMenuAdd2MacroBuilder extends PopupMenuItemSiteNodeContainer
        implements InterfaceLangOKNG {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private static final long serialVersionUID = 1L;
    private LangSelectDialog langdialog = null;
    private ParmGenMacroTrace pmt = null;
    private MacroBuilderUI mbui = null;
    private List<PRequestResponse> listprr = null;
    private List<HistoryReference> hrefs = null;

    /** @param label */
    public PopupMenuAdd2MacroBuilder(MacroBuilderUI mbui, String label) {
        super(label, true);
        this.pmt = null;
        this.mbui = mbui;
        langdialog = new LangSelectDialog(this.mbui, this, Encode.ISO_8859_1, Dialog.ModalityType.DOCUMENT_MODAL);
    }

    private String getIndentString(int i) {
        String spc = "";
        while (i-- > 0) {
            spc += " ";
        }
        return spc;
    }

    /**
     * traverse Site node tree and colloect historyreferences of leaf node.
     *
     * @param node
     * @param level
     * @param historyrefs
     */
    private void collectLeafNodes(
            StructuralNode node, int level, List<HistoryReference> historyrefs) {
        if (node.isLeaf()) {
            HistoryReference href = node.getHistoryReference();
            if (href != null) {
                historyrefs.add(href);
                LOGGER4J.debug(
                        getIndentString(level)
                                + level
                                + ":leaf name:"
                                + node.getName()
                                + " href:"
                                + href.getURI().toString());
            } else {
                LOGGER4J.debug(
                        getIndentString(level)
                                + level
                                + ":leaf name:"
                                + node.getName()
                                + " href:null");
            }
        } else {
            LOGGER4J.debug(getIndentString(level) + level + ":NO leaf name:" + node.getName());
        }
        Iterator<StructuralNode> it = node.getChildIterator();
        if (it != null) {
            while (it.hasNext()) {
                collectLeafNodes(it.next(), level + 1, historyrefs);
            }
        }
    }

    @Override
    protected void performAction(SiteNode siteNode) {
        LOGGER4J.debug("performAction called.");
        Target target = new Target(siteNode);
        if (target.getStartNodes() != null) {
            List<StructuralNode> nodes = target.getStartNodes();
            if (nodes.size() == 1 && nodes.get(0).isRoot()) { // selected root node.
                LOGGER4J.debug("ROOT:" + nodes.get(0).getName());

                Iterator<StructuralNode> iter = nodes.get(0).getChildIterator();
                while (iter.hasNext()) {
                    StructuralNode node = iter.next();
                    collectLeafNodes(node, 0, this.hrefs);
                }
            } else {
                for (StructuralNode node : nodes) {
                    collectLeafNodes(node, 0, this.hrefs);
                }
            }
        } else { // Nodes in Context scope.
            List<SiteNode> nodes = Collections.emptyList();
            if (target.isInScopeOnly()) {
                nodes = Model.getSingleton().getSession().getTopNodesInScopeFromSiteTree();
            } else if (target.getContext() != null) {
                nodes = target.getContext().getTopNodesInContextFromSiteTree();
            }
            // Loop through all of the top nodes containing children
            for (SiteNode snode : nodes) {
                StructuralNode node = new StructuralSiteNode(snode);
                collectLeafNodes(node, 0, this.hrefs);
            }
        }
    }

    @Override
    protected void performHistoryReferenceActions(List<HistoryReference> srchrefs) {
        LOGGER4J.debug("performHistoryReferenceActions called.");
        this.pmt = this.mbui.getCurrentParmGenMacroTrace();
        Invoker invoker = getInvoker();
        String invokername = invoker == null ? "null" : invoker.name();
        LOGGER4J.debug("invoker:" + invokername);

        if (invoker != Invoker.SITES_PANEL) {
            this.hrefs = srchrefs;
        } else {
            this.hrefs = new ArrayList<>();

            // collect historyReferences of leaf node from StructuralSiteNodes(Site node tree).
            for (HistoryReference historyReference : srchrefs) {
                if (historyReference != null) {
                    this.performAction(historyReference);
                }
            }
        }

        this.hrefs.stream()
                .forEach(
                        href -> {
                            System.out.println("" + href.toString());
                        });

        this.listprr =
                this.hrefs.stream()
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
            LangOK(null);
        }
    }

    @Override
    public void LangOK(Encode sequenceEncode) {
        // selected encode applied to PRequestResponses.
        if (sequenceEncode == null) {
            sequenceEncode = pmt.getSequenceEncode();
        } else {
            pmt.setSequenceEncode(sequenceEncode);
        }
        final Encode determinedEncode = sequenceEncode;
        this.listprr =
                this.hrefs.stream()
                        .map(
                                href ->
                                        new PRequestResponse(
                                                new ClientDependMessageContainer(href),
                                                determinedEncode))
                        .collect(Collectors.toList());
        mbui.addNewRequests(this.listprr);
        langdialog.setVisible(false);
    }

    @Override
    public void LangCANCEL() {
        langdialog.setVisible(false);
    }
}
