package org.zaproxy.zap.extension.automacrobuilder.zap;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.httpclient.HttpState;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.AbstractSessionManagementMethodOptionsPanel;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.SessionManagementMethodType;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;

public class AutoMacroBuilderSessionManagementMethodType extends SessionManagementMethodType {

    private static final int METHOD_IDENTIFIER = 99;

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final String METHOD_NAME = "AutoMacroBuilder Session Management";

    public static class AutoMacroBuilderSessionManagementMethod implements SessionManagementMethod {

        @Override
        public boolean isConfigured() {
            return true;
        }

        @Override
        public SessionManagementMethodType getType() {
            return new AutoMacroBuilderSessionManagementMethodType();
        }

        @Override
        public SessionManagementMethod clone() {
            return new AutoMacroBuilderSessionManagementMethod();
        }

        /**
         * no used.
         *
         * @param msg
         * @return
         */
        @Override
        public WebSession extractWebSession(HttpMessage msg) {
            return null;
        }

        /**
         * no used.<br>
         * if this functions used in other methods,<br>
         * you should define AutoMacroBuilderSession<br>
         * which is extended from WebSession.
         *
         * @return
         */
        @Override
        public WebSession createEmptyWebSession() {
            return null;
        }

        /**
         * no used.
         *
         * @param msg
         */
        @Override
        public void clearWebSessionIdentifiers(HttpMessage msg) {}

        @Override
        public ApiResponse getApiResponseRepresentation() {
            return null;
        }

        @Override
        public void processMessageToMatchSession(HttpMessage message, WebSession session)
                throws UnsupportedWebSessionException {
            if (message != null && session != null && session instanceof AutoMacroBuilderSession) {
                AutoMacroBuilderSession ambsession = (AutoMacroBuilderSession) session;
                StartedActiveScanContainer scon = ambsession.getStartedActiveScanContainer();
                ParmGenMacroTrace pmt = scon.getRunningInstance();
                if (pmt == null) { // AutoMacroBuilderSession is existed but authenticate method is
                    // NOT called in this Thread.
                    LOGGER4J.debug(
                            "authenticate method is NOT called. processMessageToMatchSession getRunningInstance returns null");
                    if (ambsession.isAlwaysAuthenticate()) {
                        // ambsession is NOT owned by this thread. we should call autheticate
                        // method.
                        LOGGER4J.debug(
                                "processMessageToMatchSession alwaysAthenticate is true, then call authenticate method.");
                        ambsession.method.authenticate(this, null, ambsession.getUser());
                    } else {
                        LOGGER4J.debug(
                                "processMessageToMatchSession alwaysAuthenticate is false, then copy pmt runningInstance and session data set to current request");
                        pmt = ambsession.getCopyInstanceForSession();
                        scon.addRunningInstance(pmt);
                        scon.addTheadid();
                    }
                }

                ParmGenMacroTrace.clientrequest.startZapCurrentRequest(pmt, message);

                if (ambsession.isAlwaysAuthenticate()) {
                    User user = ambsession.getUser();
                    user.setAuthenticatedSession(null);
                    LOGGER4J.debug(
                            "processMessageToMatchSession completed. user["
                                    + user.getName()
                                    + "] 's session set to null");
                }
            }
        }
    }

    public static class AutoMacroBuilderSession extends WebSession {
        private StartedActiveScanContainer scon = null;
        private ParmGenMacroTrace runningInstancePmtForSession = null;
        private User user = null;
        private AutoMacroBuilderAuthenticationMethodType.AutoMacroBuilderAuthenticationMethod
                method = null;

        public AutoMacroBuilderSession(
                StartedActiveScanContainer scon,
                User user,
                ParmGenMacroTrace pmt,
                AutoMacroBuilderAuthenticationMethodType.AutoMacroBuilderAuthenticationMethod
                        method) {
            super("AutoMacroBuilder Session ", new HttpState());
            this.scon = scon;
            this.runningInstancePmtForSession = pmt;
            this.user = user;
            this.method = method;
        }

        public StartedActiveScanContainer getStartedActiveScanContainer() {
            return this.scon;
        }

        public ParmGenMacroTrace getCopyInstanceForSession() {
            return this.runningInstancePmtForSession.getCopyInstanceForSession();
        }

        public User getUser() {
            return this.user;
        }

        public boolean isAlwaysAuthenticate() {
            if (this.method != null) {
                return this.method.isAlwaysAuthenticate();
            }
            return false;
        }
    }

    @Override
    public SessionManagementMethod createSessionManagementMethod(int contextId) {
        return new AutoMacroBuilderSessionManagementMethod();
    }

    @Override
    public String getName() {
        return METHOD_NAME;
    }

    @Override
    public int getUniqueIdentifier() {
        return METHOD_IDENTIFIER;
    }

    @Override
    public AbstractSessionManagementMethodOptionsPanel buildOptionsPanel(Context uiSharedContext) {
        return null;
    }

    @Override
    public boolean hasOptionsPanel() {
        return false;
    }

    @Override
    public boolean isTypeForMethod(SessionManagementMethod method) {
        return method instanceof AutoMacroBuilderSessionManagementMethod;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {}

    @Override
    public SessionManagementMethod loadMethodFromSession(Session session, int contextId)
            throws DatabaseException {
        return createSessionManagementMethod(contextId);
    }

    @Override
    public void persistMethodToSession(
            Session session, int contextId, SessionManagementMethod method)
            throws DatabaseException {}

    @Override
    public void exportData(Configuration config, SessionManagementMethod sessionMethod) {}

    @Override
    public void importData(Configuration config, SessionManagementMethod sessionMethod)
            throws ConfigurationException {}

    @Override
    public ApiDynamicActionImplementor getSetMethodForContextApiAction() {
        return null;
    }
}
