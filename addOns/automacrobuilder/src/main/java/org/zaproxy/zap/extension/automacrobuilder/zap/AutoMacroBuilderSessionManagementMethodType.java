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

public class AutoMacroBuilderSessionManagementMethodType extends SessionManagementMethodType {

    private static final int METHOD_IDENTIFIER = 99;

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final String METHOD_NAME = "AutoMacorBuilder Session Management";

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
                StartedActiveScanContainer scon =
                        ((AutoMacroBuilderSession) session).getStartedActiveScanContainer();
                ParmGenMacroTrace pmt = scon.getRunningInstance();
                ParmGenMacroTrace.clientrequest.startZapCurrentRequest(pmt, message);
            }
        }
    }

    public static class AutoMacroBuilderSession extends WebSession {
        StartedActiveScanContainer scon = null;

        public AutoMacroBuilderSession(StartedActiveScanContainer scon) {
            super("AutoMacroBuilder Session ", new HttpState());
            this.scon = scon;
        }

        public StartedActiveScanContainer getStartedActiveScanContainer() {
            return this.scon;
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
