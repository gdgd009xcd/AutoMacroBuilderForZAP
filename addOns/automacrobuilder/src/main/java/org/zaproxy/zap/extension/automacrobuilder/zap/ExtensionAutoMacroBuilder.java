/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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

import java.awt.CardLayout;
import java.awt.Font;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import javax.swing.JTextPane;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceProvider;
import org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.zap.view.MessageViewStatusPanel;
import org.zaproxy.zap.extension.sessions.ExtensionSessionManagement;
import org.zaproxy.zap.session.SessionManagementMethodType;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * An example ZAP extension which adds a top level menu item, a pop up menu item and a status panel.
 *
 * <p>{@link ExtensionAdaptor} classes are the main entry point for adding/loading functionalities
 * provided by the add-ons.
 *
 * @see #hook(ExtensionHook)
 */
public class ExtensionAutoMacroBuilder extends ExtensionAdaptor {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionAutoMacroBuilder";

    // The i18n prefix, by default the package name - defined in one place to make it easier
    // to copy and change this example
    public static final String PREFIX = "autoMacroBuilder";

    // URL for AutoMacroBuilder
    private String AMBURL = "https://gdgd009xcd.github.io/AutoMacroBuilderForZAP/";

    // private static final ImageIcon ICON =
    //        new ImageIcon(ExtensionAutoMacroBuilder.class.getResource(RESOURCES + "/cake.png"));

    // private static final String EXAMPLE_FILE = "example/ExampleFile.txt";

    private ZapMenuItem menuExample = null;
    private RightClickMsgMenu popupMsgMenuExample = null;
    private AbstractPanel statusPanel = null;
    private PopupMenuAdd2MacroBuilder popupadd2MacroBuilder = null;
    private ParmGenMacroTraceProvider pmtProvider = null;
    private ParmGenMacroTrace pmt = null;
    private MacroBuilderUI mbui = null;
    private MessageViewStatusPanel messageViewStatusPanel = null;

    // private SimpleExampleAPI api;

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public ExtensionAutoMacroBuilder() {
        super(NAME);
        setI18nPrefix(PREFIX);
        EnvironmentVariables.isSaved();
        this.pmtProvider = new ParmGenMacroTraceProvider();
        this.pmt = pmtProvider.getBaseInstance(0);

        if (this.mbui == null) {
            this.mbui = new MacroBuilderUI(this.pmtProvider, this);
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        // this.api = new SimpleExampleAPI(this);
        // extensionHook.addApiImplementor(this.api);
        ExtensionActiveScanWrapper extwrapper =
                new ExtensionActiveScanWrapper(this.pmtProvider, this.mbui);

        // As long as we're not running as a daemon
        if (getView() != null) {
            // extensionHook.getHookMenu().addToolsMenuItem(getMenuExample());
            // extensionHook.getHookMenu().addPopupMenuItem(getPopupMsgMenuExample());
            extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuAdd2MacroBuilder());
            // extensionHook.getHookView().addStatusPanel(getStatusPanel());

            this.messageViewStatusPanel = new MessageViewStatusPanel(extwrapper,
                    this.mbui,  extensionHook);
            extensionHook.getHookView().addStatusPanel(this.messageViewStatusPanel);
            extensionHook
                    .getHookView()
                    .addWorkPanel(
                            new MyWorkPanel(extwrapper, this.mbui, "MacroBuilder", extensionHook));
            // extensionHook.getHookView().addStatusPanel(new MyWorkPanel("StatusPanel", LOGGER));
            // extensionHook.getHookView().addSelectPanel(new MyWorkPanel("SelectPanel", LOGGER));
        }
        // add ScannerHook...
        LOGGER4J.debug("MyFirstScannerHook addScannerHook..");
        extensionHook.addScannerHook(
                new MyFirstScannerHook(extwrapper.getStartedActiveScanContainer()));
        // add listener
        extensionHook.addHttpSenderListener(
                new MyFirstSenderListener(extwrapper.getStartedActiveScanContainer()));

        ExtensionAuthentication extensionAuthentication =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionAuthentication.class);
        List<AuthenticationMethodType> methodTypes =
                extensionAuthentication.getAuthenticationMethodTypes();
        if (methodTypes != null) {
            methodTypes.add(new AutoMacroBuilderAuthenticationMethodType(extwrapper, this.mbui));
        }

        ExtensionSessionManagement extensionSessionManagement =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionSessionManagement.class);
        List<SessionManagementMethodType> sessMethodTypes =
                extensionSessionManagement.getSessionManagementMethodTypes();
        if (sessMethodTypes != null) {
            sessMethodTypes.add(new AutoMacroBuilderSessionManagementMethodType());
        }
        LOGGER4J.debug("succeeded getting methodTypes: size=" + methodTypes.size());
    }

    public MessageViewStatusPanel getMessageViewStatusPanel(int tabIndex) {
        this.mbui.setTabIndexOnMesssageViewTabbedPane(tabIndex);
        return this.messageViewStatusPanel;
    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        // In this example it's not necessary to override the method, as there's nothing to unload
        // manually, the components added through the class ExtensionHook (in hook(ExtensionHook))
        // are automatically removed by the base unload() method.
        // If you use/add other components through other methods you might need to free/remove them
        // here (if the extension declares that can be unloaded, see above method).
        ExtensionAuthentication extensionAuthentication =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionAuthentication.class);
        List<AuthenticationMethodType> methodTypes =
                extensionAuthentication.getAuthenticationMethodTypes();
        AuthenticationMethodType removeMethodType = null;
        for (AuthenticationMethodType mType : methodTypes) {
            if (mType.getName().equals(AutoMacroBuilderAuthenticationMethodType.METHOD_NAME)) {
                removeMethodType = mType;
            }
        }
        if (removeMethodType != null) {
            methodTypes.remove(removeMethodType);
        }
    }

    private AbstractPanel getStatusPanel() {
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new CardLayout());
            statusPanel.setName(EnvironmentVariables.getZapResourceString("autoMacroBuilder.panel.title"));
            // statusPanel.setIcon(ICON);
            JTextPane pane = new JTextPane();
            pane.setEditable(false);
            // Obtain (and set) a font with the size defined in the options
            pane.setFont(FontUtils.getFont("Dialog", Font.PLAIN));
            pane.setContentType("text/html");
            pane.setText(EnvironmentVariables.getZapResourceString("autoMacroBuilder.panel.msg"));
            statusPanel.add(pane);
        }
        return statusPanel;
    }

    private ZapMenuItem getMenuExample() {
        if (menuExample == null) {
            menuExample = new ZapMenuItem("autoMacroBuilder.topmenu.tools.title");

            menuExample.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent ae) {
                            // This is where you do what you want to do.
                            // In this case we'll just show a popup message.
                            View.getSingleton()
                                    .showMessageDialog(
                                            EnvironmentVariables.getZapResourceString(
                                                    "autoMacroBuilder.topmenu.tools.msg"));
                            // And display a file included with the add-on in the Output tab
                            displayFile("");
                        }
                    });
        }
        return menuExample;
    }

    private void displayFile(String file) {
        if (!View.isInitialised()) {
            // Running in daemon mode, shouldnt have been called
            return;
        }
        try {
            // Quick way to read a small text file
            String contents = new String("brah Brah ...");
            // Write to the output panel
            View.getSingleton().getOutputPanel().append(contents);
            // Give focus to the Output tab
            View.getSingleton().getOutputPanel().setTabFocus();
        } catch (Exception e) {
            // Something unexpected went wrong, write the error to the log
            LOGGER4J.error(e.getMessage(), e);
        }
    }

    private RightClickMsgMenu getPopupMsgMenuExample() {
        if (popupMsgMenuExample == null) {
            popupMsgMenuExample =
                    new RightClickMsgMenu(
                            this, EnvironmentVariables.getZapResourceString("autoMacroBuilder.popup.title"));
        }
        return popupMsgMenuExample;
    }

    private PopupMenuAdd2MacroBuilder getPopupMenuAdd2MacroBuilder() {
        if (popupadd2MacroBuilder == null) {
            popupadd2MacroBuilder =
                    new PopupMenuAdd2MacroBuilder(
                            this.mbui,
                            EnvironmentVariables.getZapResourceString(
                                    "autoMacroBuilder.popup.title.PopupMenuAdd2MacroBuilder"));
        }
        return popupadd2MacroBuilder;
    }

    @Override
    public String getAuthor() {
        return "gdgd009xcd";
    }

    @Override
    public String getDescription() {
        return EnvironmentVariables.getZapResourceString("autoMacroBuilder.desc");
    }

    @Override
    public URL getURL() {
        try {
            return new URL(AMBURL);
        } catch (MalformedURLException e) {
            return null;
        }
    }
}
