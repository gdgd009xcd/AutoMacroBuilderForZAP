package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.*;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.authentication.AbstractAuthenticationMethodOptionsPanel;
import org.zaproxy.zap.authentication.AbstractCredentialsOptionsPanel;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.automacrobuilder.PRequestResponse;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceParams;
import org.zaproxy.zap.extension.automacrobuilder.ParmVars;
import org.zaproxy.zap.extension.automacrobuilder.ThreadManagerProvider;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.extension.automacrobuilder.view.RequestListJDialog;
import org.zaproxy.zap.extension.sessions.ContextSessionManagementPanel;
import org.zaproxy.zap.extension.sessions.ExtensionSessionManagement;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.LayoutHelper;

public class AutoMacroBuilderAuthenticationMethodType extends AuthenticationMethodType {
    public static final String CONTEXT_CONFIG_AUTH_AUTOMACRO =
            AuthenticationMethod.CONTEXT_CONFIG_AUTH + ".automacro";
    public static final String CONTEXT_CONFIG_AUTH_AUTOMACRO_ITEMS =
            CONTEXT_CONFIG_AUTH_AUTOMACRO + ".itemno";
    public static final String CONTEXT_CONFIG_AUTH_AUTOMACRO_OTHERS =
            CONTEXT_CONFIG_AUTH_AUTOMACRO + ".others";
    private static String API_METHOD_NAME = "autoMacroBuilderAuthentication";
    public static String METHOD_NAME = "autoMacroBuilderMethod";
    private static String TARGET_SELECT_NAME_LABEL = "Target:";
    private static String ALWAYS_AUTH_NAME_LABEL = "Always authenticate";
    private MacroBuilderUI mbUI;
    private ExtensionActiveScanWrapper extwrapper;

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public AutoMacroBuilderAuthenticationMethodType(
            ExtensionActiveScanWrapper extwrapper, MacroBuilderUI mbUI) {
        super();
        this.mbUI = mbUI;
        this.extwrapper = extwrapper;
    }

    public class AutoMacroBuilderAuthenticationMethod extends AuthenticationMethod {

        private int itemNo;
        private String projectFilename;
        private int tabIndex;
        private int targetStepNo;
        private boolean alwaysAuthenticate;
        private MacroBuilderUI mbUI;
        private ExtensionActiveScanWrapper extwrapper;
        HttpSender httpSender = null;

        AutoMacroBuilderAuthenticationMethod(
                ExtensionActiveScanWrapper extwrapper,
                MacroBuilderUI mbUI,
                int itemno,
                String projectFilename,
                int tabIndex,
                int targetStepNo,
                boolean alwaysAuthenticate) {
            this.extwrapper = extwrapper;
            this.mbUI = mbUI;
            this.itemNo = itemno;
            this.projectFilename = projectFilename;
            this.tabIndex = tabIndex;
            this.targetStepNo = targetStepNo;
            this.alwaysAuthenticate = alwaysAuthenticate;
        }

        public boolean isAlwaysAuthenticate() {
            return this.alwaysAuthenticate;
        }

        /**
         * authenticate information is fullfilled or not<br>
         * e.g.: username/password is provided or not
         *
         * @return
         */
        @Override
        public boolean isConfigured() {
            return true;
        }

        /**
         * return deep-copy of this class
         *
         * @return
         */
        @Override
        protected AuthenticationMethod duplicate() {
            return new AutoMacroBuilderAuthenticationMethod(
                    this.extwrapper,
                    this.mbUI,
                    this.itemNo,
                    this.projectFilename,
                    this.tabIndex,
                    this.targetStepNo,
                    this.alwaysAuthenticate);
        }

        /**
         * required creadential names for authentication information.<br>
         * credential names: List of parameter names required for authentication
         *
         * @return
         */
        @Override
        public AuthenticationCredentials createAuthenticationCredentials() {
            return new AutoMacroBuilderAuthenticationCredentials();
        }

        @Override
        public AuthenticationMethodType getType() {
            return new AutoMacroBuilderAuthenticationMethodType(this.extwrapper, this.mbUI);
        }

        /**
         * main routine for authentication action which provided by AutoMacroBuilder
         *
         * @param sessionManagementMethod
         * @param authenticationCredentials
         * @param user
         * @return
         * @throws UnsupportedAuthenticationCredentialsException
         */
        @Override
        public WebSession authenticate(
                SessionManagementMethod sessionManagementMethod,
                AuthenticationCredentials authenticationCredentials,
                User user)
                throws UnsupportedAuthenticationCredentialsException {
            LOGGER4J.info("authenticate called.");
            ParmGenMacroTrace pmt = this.mbUI.getParmGenMacroTraceAtTabIndex(this.tabIndex);
            int subSequenceScanLimit = this.mbUI.getSubSequenceScanLimit();
            int lastStepNo = pmt.getLastStepNo(this.targetStepNo, subSequenceScanLimit);
            final ParmGenMacroTraceParams pmtParams =
                    new ParmGenMacroTraceParams(this.targetStepNo, lastStepNo, this.tabIndex);
            StartedActiveScanContainer scon = this.extwrapper.getStartedActiveScanContainer();
            scon.addParmGenMacroTraceParams(pmtParams);
            BeforeMacroDoActionProvider beforemacroprovider = new BeforeMacroDoActionProvider();
            scon.addTheadid();
            beforemacroprovider.setParameters(
                    scon, null, HttpSender.MANUAL_REQUEST_INITIATOR, getHttpSender());
            ThreadManagerProvider.getThreadManager().beginProcess(beforemacroprovider);
            ParmGenMacroTrace runningInstancePmt = scon.getRunningInstance();

            WebSession wsession = null;
            if (sessionManagementMethod
                    instanceof
                    AutoMacroBuilderSessionManagementMethodType
                            .AutoMacroBuilderSessionManagementMethod) {
                wsession =
                        new AutoMacroBuilderSessionManagementMethodType.AutoMacroBuilderSession(
                                scon, user, runningInstancePmt.getCopyInstanceForSession(), this);
            } else {
                int beginProcessLastStepNo = this.targetStepNo - 1;
                PRequestResponse pRequestResponseForSession =
                        pmt.getPRequestResponseFromSaveList(beginProcessLastStepNo);
                if (pRequestResponseForSession == null) {
                    pRequestResponseForSession = pmt.getCurrentRequestResponse();
                }
                if (pRequestResponseForSession != null) {
                    HttpMessage htmess = ZapUtil.getHttpMessage(pRequestResponseForSession);
                    wsession = sessionManagementMethod.extractWebSession(htmess);
                }
                if (wsession == null) {
                    wsession = sessionManagementMethod.createEmptyWebSession();
                }
            }
            return wsession;
        }

        /**
         * get representation of API response<br>
         * API URL:
         * http://localhost:8040/JSON/authentication/view/getAuthenticationMethod/?apikey=xxxxxxx&contextId=2
         * <br>
         * API response: "{"method":{"methodName":"AutoMacroBuilderAuthentication"}}"
         *
         * @return
         */
        @Override
        public ApiResponse getApiResponseRepresentation() {
            Map<String, String> values = new HashMap<>();
            values.put("methodName", API_METHOD_NAME);
            return new AuthMethodApiResponseRepresentation<>(values);
        }

        protected HttpSender getHttpSender() {
            if (this.httpSender == null) {
                this.httpSender =
                        new HttpSender(
                                Model.getSingleton().getOptionsParam().getConnectionParam(),
                                true,
                                HttpSender.AUTHENTICATION_INITIATOR);
            }
            return httpSender;
        }
    }

    public enum TargetSelectItem {
        PRE(0),
        POST(1),
        SELECTED(2);

        private final int i;
        private final String name;

        TargetSelectItem(int i) {
            this.i = i;
            this.name = toString();
        }

        public int getInt() {
            return this.i;
        }

        public String getName() {
            return this.name;
        }

        public static String[] getItemStrings() {
            TargetSelectItem[] items = TargetSelectItem.values();
            String[] itemnames = new String[items.length];
            int i = 0;
            for (TargetSelectItem item : items) {
                itemnames[i++] = item.name;
            }
            return itemnames;
        }

        public static int getInt(String name) {
            try {
                TargetSelectItem item = TargetSelectItem.valueOf(name);
                int i = item.getInt();
                return i;
            } catch (IllegalArgumentException e) {

            }
            return -1;
        }

        public static String getName(int i) {
            TargetSelectItem[] items = TargetSelectItem.values();
            for (TargetSelectItem item : items) {
                if (item.getInt() == i) {
                    return item.getName();
                }
            }
            return null;
        }
    }

    @SuppressWarnings("serial")
    public class AutoMacroBuilderAuthenticationMethodOptionsPanel
            extends AbstractAuthenticationMethodOptionsPanel {

        private AutoMacroBuilderAuthenticationMethod method;
        private JComboBox<String> targetSelectComboBox;
        private JCheckBox alwaysAuthenticateCheckBox;
        private JButton projectLoad;
        private JButton tabIndexConfig;
        private JTextField projectFileName;
        private JTextField tabIndex;
        private JTextField targetStepNo;
        private MacroBuilderUI mbUI;
        private ExtensionUserManagement userExt = null;
        private Context context = null;
        private boolean firstCalled = true;

        public AutoMacroBuilderAuthenticationMethodOptionsPanel(
                MacroBuilderUI mbUI, Context context) {
            super();
            firstCalled = true;
            this.context = context;

            initialize(mbUI);
        }

        public MacroBuilderUI getMacroBuilderUI() {
            return this.mbUI;
        }

        private void initialize(MacroBuilderUI mbUI) {
            this.mbUI = mbUI;
            int rowy = 0;
            double weightx = 1;
            double weighty = 1;
            LOGGER4J.debug("initialize called");
            this.setLayout(new GridBagLayout());

            // row 0
            this.add(
                    new JLabel(TARGET_SELECT_NAME_LABEL),
                    LayoutHelper.getGBC(0, rowy, 1, 0.0d, 0.0d));
            String[] combodata = TargetSelectItem.getItemStrings();
            DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>(combodata);
            this.targetSelectComboBox = new JComboBox<>(model);
            this.targetSelectComboBox.setSelectedIndex(0);
            this.targetSelectComboBox.setEnabled(false);
            this.add(this.targetSelectComboBox, LayoutHelper.getGBC(1, rowy, 4, 1.0d, 0.0d));
            this.targetSelectComboBox.addActionListener(
                    e -> {
                        if (this.method != null) {
                            this.method.itemNo = targetSelectComboBox.getSelectedIndex();
                            LOGGER4J.debug("selected item:" + this.method.itemNo);
                        } else {
                            LOGGER4J.debug("method is NULL");
                        }
                    });
            rowy++;
            // row 1
            this.alwaysAuthenticateCheckBox = new JCheckBox(ALWAYS_AUTH_NAME_LABEL);
            this.alwaysAuthenticateCheckBox.setSelected(true);
            this.add(this.alwaysAuthenticateCheckBox, LayoutHelper.getGBC(0, rowy, 5, 1.0d, 0.0d));
            this.alwaysAuthenticateCheckBox.addActionListener(
                    e -> {
                        if (this.method != null) {
                            this.method.alwaysAuthenticate =
                                    this.alwaysAuthenticateCheckBox.isSelected();
                            LOGGER4J.debug(
                                    "alwaysAuthenticate: "
                                            + (this.method.alwaysAuthenticate ? "TRUE" : "FALSE"));
                        } else {
                            LOGGER4J.debug("method is NULL");
                        }
                    });
            rowy++;

            // row 2
            this.projectLoad = new JButton("Load");
            this.add(this.projectLoad, LayoutHelper.getGBC(0, rowy, 1, 0.0d, 0.0d));

            this.projectFileName = new JTextField();
            this.projectFileName.setText(ParmVars.getParmFile());
            this.add(this.projectFileName, LayoutHelper.getGBC(1, rowy, 4, 1.0d, 0.0d));
            this.projectLoad.addActionListener(
                    e -> {
                        if (this.mbUI.loadProject()) {
                            this.projectFileName.setText(ParmVars.getParmFile());
                            int currentTabIndexVal =
                                    this.mbUI.getMacroRequestListTabsCurrentIndex();
                            this.tabIndex.setText(Integer.toString(currentTabIndexVal));
                            ParmGenMacroTrace pmt =
                                    this.mbUI.getParmGenMacroTraceAtTabIndex(currentTabIndexVal);
                            if (pmt != null) {
                                int currentTargetStepNo = pmt.getCurrentRequestPos();
                                this.targetStepNo.setText(Integer.toString(currentTargetStepNo));
                            }
                        }
                    });
            rowy++;
            // row 3
            this.tabIndexConfig = new JButton("Config");
            this.tabIndexConfig.addActionListener(
                    e -> {
                        new RequestListJDialog(this).setVisible(true);
                    });
            this.add(this.tabIndexConfig, LayoutHelper.getGBC(0, rowy, 1, 2, 0.0d, 0.0d));
            this.add(
                    new JLabel("TabIndex No:"),
                    LayoutHelper.getGBC(
                            1,
                            rowy,
                            1,
                            0.2d,
                            0.0d,
                            GridBagConstraints.NONE,
                            GridBagConstraints.EAST,
                            null));
            this.tabIndex = new JTextField();
            this.add(this.tabIndex, LayoutHelper.getGBC(2, rowy, 2, 0.8d, 0.0d));
            rowy++;
            // row 4
            this.add(
                    new JLabel("Target Request No:"),
                    LayoutHelper.getGBC(
                            1,
                            rowy,
                            1,
                            0.2d,
                            0.0d,
                            GridBagConstraints.NONE,
                            GridBagConstraints.EAST,
                            null));
            this.targetStepNo = new JTextField();
            this.add(this.targetStepNo, LayoutHelper.getGBC(2, rowy, 2, 0.8d, 0.0d));
        }

        /**
         * Whether the field value was entered correctly, otherwise throw IllegalStateException
         *
         * @throws IllegalStateException
         */
        @Override
        public void validateFields() throws IllegalStateException {
            String projectFileName = this.projectFileName.getText();
            if (projectFileName == null || projectFileName.isEmpty()) {
                throw new IllegalStateException(
                        "projectFileName is empty or null. please load it.");
            } else {
                String loadedProjectFileName = ParmVars.getParmFile();
                if (!loadedProjectFileName.equals(projectFileName) || !ParmVars.isSaved()) {
                    throw new IllegalStateException("No loaded projectFileName:" + projectFileName);
                }
            }
            int tabIndexVal = ZapUtil.parseInt(this.tabIndex.getText(), -1);
            int targetStepNoVal = ZapUtil.parseInt(this.targetStepNo.getText(), -1);
            List<PRequestResponse> rList = this.mbUI.getPRequestResponseListAtTabIndex(tabIndexVal);
            if (rList == null) {
                throw new IllegalStateException("Illegal tabIndex:" + tabIndexVal);
            }
            if (rList.size() <= targetStepNoVal || targetStepNoVal < 0) {
                throw new IllegalStateException("Illegal targetStepNo:" + targetStepNoVal);
            }
        }

        /**
         * actionPerformed when session properity's<br>
         * OK button is pressed
         */
        @Override
        public void saveMethod() {
            this.method.itemNo = this.targetSelectComboBox.getSelectedIndex();
            this.method.projectFilename = this.projectFileName.getText();
            this.method.tabIndex = ZapUtil.parseInt(this.tabIndex.getText(), -1);
            this.method.targetStepNo = ZapUtil.parseInt(this.targetStepNo.getText(), -1);
            this.method.alwaysAuthenticate = this.alwaysAuthenticateCheckBox.isSelected();
            // save dummy User for authenticate
            ExtensionUserManagement userExt = getUserExt();
            if (userExt != null && userExt.getUIConfiguredUsers(context.getId()).size() == 0) {
                AutoMacroBuilderAuthenticationCredentials credentials =
                        createAuthenticationCredentials();
                User user = new User(this.context.getId(), "AMBDUMMYUSER");
                user.setAuthenticationCredentials(credentials);
                user.setEnabled(true);
                userExt.getContextUserAuthManager(context.getId()).addUser(user);
                userExt.addSharedContextUser(context, user);
                LOGGER4J.debug("AMBDUMMYUSER added to Context id:" + context.getId());
            }
            LOGGER4J.debug("saveMethod called itemNo:" + this.method.itemNo);
        }

        @Override
        public void bindMethod(AuthenticationMethod authenticationMethod)
                throws UnsupportedAuthenticationMethodException {
            this.method = (AutoMacroBuilderAuthenticationMethod) authenticationMethod;
            this.targetSelectComboBox.setSelectedIndex(this.method.itemNo);
            this.tabIndex.setText(
                    this.method.tabIndex == -1 ? "" : String.valueOf(this.method.tabIndex));
            this.targetStepNo.setText(
                    this.method.targetStepNo == -1 ? "" : String.valueOf(this.method.targetStepNo));
            this.alwaysAuthenticateCheckBox.setSelected(this.method.alwaysAuthenticate);
            LOGGER4J.debug("bindMethod called itemNo:" + this.method.itemNo);
            if (this.firstCalled) {
                LOGGER4J.debug("firstCalled in bindMethod");
                ExtensionSessionManagement extensionSessionManagement =
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionSessionManagement.class);
                ContextSessionManagementPanel conpanel =
                        (ContextSessionManagementPanel)
                                extensionSessionManagement.getContextPanel(this.context);
                this.context.setSessionManagementMethod(
                        new AutoMacroBuilderSessionManagementMethodType
                                .AutoMacroBuilderSessionManagementMethod());
                conpanel.initContextData(null, this.context);
                this.firstCalled = false;
            }
        }

        @Override
        public AuthenticationMethod getMethod() {
            LOGGER4J.debug("getMethod called.");
            return this.method;
        }

        public int getTabIndex() {
            return ZapUtil.parseInt(tabIndex.getText(), -1);
        }

        public int getTargetStepNo() {
            return ZapUtil.parseInt(targetStepNo.getText(), -1);
        }

        public void setTabIndex(int tabIndexVal) {
            String tabIndexString = ZapUtil.int2String(tabIndexVal, "");
            this.tabIndex.setText(tabIndexString);
        }

        public void setTergetStepNo(int targetStepNoVal) {
            String targetStepNoString = ZapUtil.int2String(targetStepNoVal, "");
            this.targetStepNo.setText(targetStepNoString);
        }

        private ExtensionUserManagement getUserExt() {
            if (userExt == null) {
                userExt =
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionUserManagement.class);
            }
            return userExt;
        }
    }

    @Override
    public AutoMacroBuilderAuthenticationMethod createAuthenticationMethod(int i) {
        LOGGER4J.debug("createAuthenticationMethod called");
        String projectFileName = "";
        int currentTabIndexVal = -1;
        int currentTargetStepNo = -1;
        if (ParmVars.isSaved()) {
            projectFileName = ParmVars.getParmFile();
            currentTabIndexVal = this.mbUI.getMacroRequestListTabsCurrentIndex();
            ParmGenMacroTrace pmt = this.mbUI.getParmGenMacroTraceAtTabIndex(currentTabIndexVal);
            if (pmt != null) {
                currentTargetStepNo = pmt.getCurrentRequestPos();
            }
        }
        return new AutoMacroBuilderAuthenticationMethod(
                this.extwrapper,
                this.mbUI,
                0,
                projectFileName,
                currentTabIndexVal,
                currentTargetStepNo,
                true);
    }

    @Override
    public String getName() {
        return METHOD_NAME;
    }

    @Override
    public int getUniqueIdentifier() {
        return 101;
    }

    @Override
    public AbstractAuthenticationMethodOptionsPanel buildOptionsPanel(Context context) {
        return new AutoMacroBuilderAuthenticationMethodOptionsPanel(this.mbUI, context);
    }

    @Override
    public boolean hasOptionsPanel() {
        return true;
    }

    @Override
    public AbstractCredentialsOptionsPanel<? extends AuthenticationCredentials>
            buildCredentialsOptionsPanel(
                    AuthenticationCredentials authenticationCredentials, Context context) {
        LOGGER4J.debug("buildCredentialsOptionsPanel called.");
        return new AutoMacroBuilderAuthenticationCredentials
                .AutoMacroBuilderAuthenticationCredentialsOptionsPanel(
                (AutoMacroBuilderAuthenticationCredentials) authenticationCredentials);
    }

    @Override
    public boolean hasCredentialsOptionsPanel() {
        return true;
    }

    @Override
    public boolean isTypeForMethod(AuthenticationMethod authenticationMethod) {
        return (authenticationMethod instanceof AutoMacroBuilderAuthenticationMethod);
    }

    /**
     * hook when initial load this authentication type<br>
     * e.g. create popup menu for this authentication
     *
     * @param extensionHook
     */
    @Override
    public void hook(ExtensionHook extensionHook) {}

    /**
     * load this authentication parameter values from session, set these to AuthenticationMethod
     *
     * @param session
     * @param contextId
     * @return
     * @throws DatabaseException
     */
    @Override
    public AutoMacroBuilderAuthenticationMethod loadMethodFromSession(
            Session session, int contextId) throws DatabaseException {
        AutoMacroBuilderAuthenticationMethod method = createAuthenticationMethod(contextId);
        List<String> names =
                session.getContextDataStrings(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_1);
        if (names != null && names.size() > 1) {
            String name = names.get(0);
            int itemno = TargetSelectItem.getInt(name);
            method.itemNo = itemno;
            String boolValue = names.get(1);
            if (boolValue.equals("TRUE")) {
                method.alwaysAuthenticate = true;
            } else {
                method.alwaysAuthenticate = false;
            }
        }
        List<String> otherDatas =
                session.getContextDataStrings(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_2);
        if (otherDatas != null && otherDatas.size() > 2) {
            String projectFileName = otherDatas.get(0);
            String tabIndexString = otherDatas.get(1);
            String targetStepNoString = otherDatas.get(2);
            if (this.mbUI.loadProjectFromFile(projectFileName)) {
                method.projectFilename = projectFileName;
                int tabIndex = Integer.parseInt(tabIndexString);
                int targetStepNo = Integer.parseInt(targetStepNoString);
                if (tabIndex < this.mbUI.getMacroRequestTabCount()) {
                    method.tabIndex = tabIndex;
                    ParmGenMacroTrace pmt =
                            this.mbUI.getParmGenMacroTraceAtTabIndex(method.tabIndex);
                    if (pmt != null) {
                        if (pmt.getRequestListSize() > targetStepNo) {
                            method.targetStepNo = targetStepNo;
                        }
                    }
                }
            }
        }
        return method;
    }

    /**
     * save this authentication parameter values to session
     *
     * @param session
     * @param contextId
     * @param authenticationMethod
     * @throws DatabaseException
     */
    @Override
    public void persistMethodToSession(
            Session session, int contextId, AuthenticationMethod authenticationMethod)
            throws UnsupportedAuthenticationMethodException, DatabaseException {
        if (!(authenticationMethod
                instanceof
                AutoMacroBuilderAuthenticationMethodType.AutoMacroBuilderAuthenticationMethod))
            throw new UnsupportedAuthenticationMethodException(
                    "AutoMacroBuilder authentication type only supports: "
                            + AutoMacroBuilderAuthenticationMethodType
                                    .AutoMacroBuilderAuthenticationMethod.class);
        AutoMacroBuilderAuthenticationMethod method =
                (AutoMacroBuilderAuthenticationMethod) authenticationMethod;
        String itemName = TargetSelectItem.getName(method.itemNo);
        String alwaysAuthenticateBoolValue = method.alwaysAuthenticate ? "TRUE" : "FALSE";
        List<String> names = new ArrayList<>();
        names.add(itemName);
        names.add(alwaysAuthenticateBoolValue);
        session.setContextData(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_1, names);
        List<String> otherDatas = new ArrayList<>();
        otherDatas.add(method.projectFilename);
        String tabIndexString = Integer.toString(method.tabIndex);
        otherDatas.add(tabIndexString);
        String targetStepNoString = Integer.toString(method.targetStepNo);
        otherDatas.add(targetStepNoString);
        session.setContextData(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_2, otherDatas);
    }

    @Override
    public void exportData(Configuration configuration, AuthenticationMethod authenticationMethod)
            throws UnsupportedAuthenticationMethodException {
        if (!(authenticationMethod
                instanceof
                AutoMacroBuilderAuthenticationMethodType.AutoMacroBuilderAuthenticationMethod))
            throw new UnsupportedAuthenticationMethodException(
                    "AutoMacroBuilder authentication type only supports: "
                            + AutoMacroBuilderAuthenticationMethodType
                                    .AutoMacroBuilderAuthenticationMethod.class);
        AutoMacroBuilderAuthenticationMethod method =
                (AutoMacroBuilderAuthenticationMethod) authenticationMethod;
        String itemNoString = TargetSelectItem.getName(method.itemNo);
        configuration.setProperty(CONTEXT_CONFIG_AUTH_AUTOMACRO_ITEMS, itemNoString);
        String alwaysAuthBoolValue = method.alwaysAuthenticate ? "TRUE" : "FALSE";
        configuration.addProperty(CONTEXT_CONFIG_AUTH_AUTOMACRO_ITEMS, alwaysAuthBoolValue);
        configuration.setProperty(CONTEXT_CONFIG_AUTH_AUTOMACRO_OTHERS, method.projectFilename);
        String tabIndexString = Integer.toString(method.tabIndex);
        configuration.addProperty(CONTEXT_CONFIG_AUTH_AUTOMACRO_OTHERS, tabIndexString);
        String targetStepNoString = Integer.toString(method.targetStepNo);
        configuration.addProperty(CONTEXT_CONFIG_AUTH_AUTOMACRO_OTHERS, targetStepNoString);
    }

    @Override
    public void importData(Configuration configuration, AuthenticationMethod authenticationMethod)
            throws ConfigurationException {
        if (!(authenticationMethod
                instanceof
                AutoMacroBuilderAuthenticationMethodType.AutoMacroBuilderAuthenticationMethod))
            throw new UnsupportedAuthenticationMethodException(
                    "AutoMacroBuilder authentication type only supports: "
                            + AutoMacroBuilderAuthenticationMethodType
                                    .AutoMacroBuilderAuthenticationMethod.class);
        AutoMacroBuilderAuthenticationMethod method =
                (AutoMacroBuilderAuthenticationMethod) authenticationMethod;
        List<String> itemNos =
                objListToStrList(configuration.getList(CONTEXT_CONFIG_AUTH_AUTOMACRO_ITEMS));
        if (itemNos != null && itemNos.size() > 1) {
            String name = itemNos.get(0);
            int itemno = TargetSelectItem.getInt(name);
            method.itemNo = itemno;
            String boolValue = itemNos.get(1);
            if (boolValue.equals("TRUE")) {
                method.alwaysAuthenticate = true;
            } else {
                method.alwaysAuthenticate = false;
            }
        }

        List<String> others =
                objListToStrList(configuration.getList(CONTEXT_CONFIG_AUTH_AUTOMACRO_OTHERS));
        if (others != null && others.size() > 2) {
            String projectFileName = others.get(0);
            String tabIndexString = others.get(1);
            String targetStepNoString = others.get(2);
            if (this.mbUI.loadProjectFromFile(projectFileName)) {
                method.projectFilename = projectFileName;
                int tabIndex = Integer.parseInt(tabIndexString);
                int targetStepNo = Integer.parseInt(targetStepNoString);
                if (tabIndex < this.mbUI.getMacroRequestTabCount()) {
                    method.tabIndex = tabIndex;
                    ParmGenMacroTrace pmt =
                            this.mbUI.getParmGenMacroTraceAtTabIndex(method.tabIndex);
                    if (pmt != null) {
                        if (pmt.getRequestListSize() < targetStepNo) {
                            method.targetStepNo = targetStepNo;
                        }
                    }
                }
            }
        }
    }

    private List<String> objListToStrList(List<Object> oList) {
        List<String> sList = new ArrayList<>();
        if (oList != null) {
            for (Object o : oList) {
                sList.add(o.toString());
            }
        }
        return sList;
    }

    @Override
    public AutoMacroBuilderAuthenticationCredentials createAuthenticationCredentials() {
        return new AutoMacroBuilderAuthenticationCredentials("default", "password");
    }

    @Override
    public Class<AutoMacroBuilderAuthenticationCredentials> getAuthenticationCredentialsType() {
        return AutoMacroBuilderAuthenticationCredentials.class;
    }

    @Override
    public ApiDynamicActionImplementor getSetMethodForContextApiAction() {
        return null;
    }

    @Override
    public ApiDynamicActionImplementor getSetCredentialsForUserApiAction() {
        return null;
    }

    static class AuthMethodApiResponseRepresentation<T> extends ApiResponseSet<T> {

        public AuthMethodApiResponseRepresentation(Map<String, T> values) {
            super("method", values);
        }

        @Override
        public JSON toJSON() {
            JSONObject response = new JSONObject();
            response.put(getName(), super.toJSON());
            return response;
        }
    }
}
