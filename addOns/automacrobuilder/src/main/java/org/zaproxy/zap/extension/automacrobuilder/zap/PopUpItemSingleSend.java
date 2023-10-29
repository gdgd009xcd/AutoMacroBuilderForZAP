package org.zaproxy.zap.extension.automacrobuilder.zap;

import static org.zaproxy.zap.extension.automacrobuilder.zap.ExtensionAutoMacroBuilder.PREFIX;

import java.io.IOException;
import javax.swing.*;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.extension.automacrobuilder.PRequest;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceParams;
import org.zaproxy.zap.extension.automacrobuilder.ThreadManagerProvider;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.model.SessionStructure;

@SuppressWarnings("serial")
public class PopUpItemSingleSend extends JMenuItem {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private HttpSender sender = null;

    @Deprecated
    private static HttpMethodHelper helper = new HttpMethodHelper();

    private BeforeMacroDoActionProvider beforemacroprovider = null;
    private PostMacroDoActionProvider postmacroprovider = null;
    private ExtensionHistory extensionHistory = null;

    PopUpItemSingleSend(
            MacroBuilderUI mbui,
            StartedActiveScanContainer acon,
            BeforeMacroDoActionProvider beforemacroprovider,
            PostMacroDoActionProvider postmacroprovider) {
        super(Constant.messages.getString(PREFIX + ".popup.title.PopUpSingleSendForMacroBuilder"));
        this.beforemacroprovider = beforemacroprovider;
        this.postmacroprovider = postmacroprovider;

        final StartedActiveScanContainer f_acon = acon;
        final MacroBuilderUI f_mbui = mbui;

        addActionListener(
                e -> {
                    PRequest newrequest = ZapUtil.getPRequestFromMacroRequest(f_mbui);

                    if (newrequest != null) {
                        int selectedTabIndex = f_mbui.getSelectedTabIndexOfMacroRequestList();
                        int currentSelectedPos =
                                f_mbui.getRequestJListSelectedIndexAtTabIndex(selectedTabIndex);
                        ParmGenMacroTrace pmt =
                                f_mbui.getParmGenMacroTraceAtTabIndex(selectedTabIndex);
                        int subSequenceScanLimit = f_mbui.getSubSequenceScanLimit();
                        int lastStepNo =
                                pmt.getLastStepNo(currentSelectedPos, subSequenceScanLimit);
                        final HttpMessage htmess = ZapUtil.getHttpMessage(newrequest);
                        final ParmGenMacroTraceParams pmtParams =
                                new ParmGenMacroTraceParams(
                                        currentSelectedPos, lastStepNo, selectedTabIndex);
                        final Thread t =
                                new Thread(
                                        new Runnable() {
                                            @Override
                                            public void run() {
                                                try {
                                                    f_acon.addParmGenMacroTraceParams(pmtParams);
                                                    HttpSender sender = getHttpSenderInstance();
                                                    beforemacroprovider.setParameters(
                                                            f_acon,
                                                            htmess,
                                                            HttpSender.MANUAL_REQUEST_INITIATOR,
                                                            sender);
                                                    ThreadManagerProvider.getThreadManager()
                                                            .beginProcess(beforemacroprovider);
                                                    htmess.setTimeSentMillis(
                                                            System.currentTimeMillis());
                                                    pmt.send(sender, htmess);
                                                    postmacroprovider.setParameters(
                                                            f_acon,
                                                            htmess,
                                                            HttpSender.MANUAL_REQUEST_INITIATOR,
                                                            sender);
                                                    ThreadManagerProvider.getThreadManager()
                                                            .beginProcess(postmacroprovider);

                                                    Session session = Model.getSingleton().getSession();
                                                    HistoryReference ref =
                                                            new HistoryReference(session, HistoryReference.TYPE_ZAP_USER, htmess);
                                                    final ExtensionHistory extHistory = getHistoryExtension();
                                                    if (extHistory != null) {
                                                        extHistory.addHistory(ref);
                                                    }
                                                    SessionStructure.addPath(Model.getSingleton(), ref, htmess);// must add SiteNode Tree.
                                                } catch (Exception exception) {
                                                    LOGGER4J.error(exception.getMessage(), exception);
                                                } finally {
                                                    shutdownHttpSender();
                                                }
                                            }
                                        });
                        t.start();
                        try {
                            t.join();
                        } catch (InterruptedException ex) {
                            LOGGER4J.error("", ex);
                        }
                        SwingUtilities.invokeLater(
                                () -> {
                                    f_mbui.updateCurrentSelectedRequestListDisplayContents();
                                });
                    }
                });
    }

    /**
     * Get HttpSender Instance
     *
     * <P>no need to use sender.shutdown.</P>
     */
    public HttpSender getHttpSenderInstance() {
        if (sender == null) {
            sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
        }
        return sender;
    }

    private ExtensionHistory getHistoryExtension() {
        if (this.extensionHistory == null) {
            this.extensionHistory = Control.getSingleton()
                    .getExtensionLoader()
                    .getExtension(
                            ExtensionHistory
                                    .class);
        }
        return this.extensionHistory;
    }
    /**
     * shudown HttpSender instance
     *
     * <p>and initialize it's parameter to null
     */
    public void shutdownHttpSender() {
        if (sender != null) {
            sender = null;
        }
    }

    @Deprecated
    private HttpMethod runMethod(HttpMessage msg) throws IOException {
        HttpMethod method = null;

        // HttpMethodParams params = new HttpMethodParams();
        // int sotimeout = params.getSoTimeout();
        // LOGGER4J.debug("default timeout:" + sotimeout);

        method = helper.createRequestMethod(msg.getRequestHeader(), msg.getRequestBody());
        HttpMethodParams params = method.getParams();
        int sotimeout = params.getSoTimeout();
        LOGGER4J.debug("default timeout:" + sotimeout);

        // Anyway, We disable followredirects
        method.setFollowRedirects(false);

        // ZAP: Use custom HttpState if needed

        getHttpSenderInstance().executeMethod(method, null);

        HttpMethodHelper.updateHttpRequestHeaderSent(msg.getRequestHeader(), method);

        return method;
    }

    @Deprecated
    private void send(HttpMessage msg) throws IOException {
        boolean isFollowRedirect = false;
        HttpMethod method = null;
        HttpResponseHeader resHeader = null;
        long starttime = 0;

        try {
            starttime = System.currentTimeMillis();
            method = runMethod(msg);
            // successfully executed;
            resHeader = HttpMethodHelper.getHttpResponseHeader(method);
            resHeader.setHeader(
                    HttpHeader.TRANSFER_ENCODING,
                    null); // replaceAll("Transfer-Encoding: chunked\r\n",
            // "");
            msg.setResponseHeader(resHeader);
            msg.getResponseBody().setCharset(resHeader.getCharset());
            msg.getResponseBody().setLength(0);

            // ZAP: Do not read response body for Server-Sent Events stream
            // ZAP: Moreover do not set content length to zero
            if (!msg.isEventStream()) {
                msg.getResponseBody().append(method.getResponseBody());
            }
            msg.setResponseFromTargetHost(true);

            // ZAP: set method to retrieve upgraded channel later
            // if (method instanceof ZapGetMethod) {
            //    msg.setUserObject(method);
            // }
        } finally {
            if (method != null) {
                method.releaseConnection();
            }
            // shutdownHttpSender();
            LOGGER4J.debug("release Connection and shutdown completed.");
            long endtime = System.currentTimeMillis();
            LOGGER4J.debug("runMethod lapse : " + (endtime - starttime) / 1000 + "sec.");
        }
    }
}
