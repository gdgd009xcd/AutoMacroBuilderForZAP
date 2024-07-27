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
package org.zaproxy.zap.extension.automacrobuilder.zap;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTraceProvider;
import org.zaproxy.zap.extension.automacrobuilder.ThreadManagerProvider;
import org.zaproxy.zap.extension.forceduser.ExtensionForcedUser;
import org.zaproxy.zap.network.HttpSenderListener;

public class MyFirstSenderListener implements HttpSenderListener {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    public static final int DEFAULT_EXTENSION_LISTENER_ORDER = 10000;// this value must be larger than ExtensionForcedUser.getListenerOrder()==9998
    private int listerOrder = DEFAULT_EXTENSION_LISTENER_ORDER;
    private StartedActiveScanContainer startedcon = null;
    private BeforeMacroDoActionProvider beforemacroprovider = new BeforeMacroDoActionProvider();
    private PostMacroDoActionProvider postmacroprovider = new PostMacroDoActionProvider();

    MyFirstSenderListener(StartedActiveScanContainer startedcon) {

        this.startedcon = startedcon;
        ExtensionForcedUser extensionForcedUser =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionForcedUser.class);
        if (extensionForcedUser != null) {
            int forcedUserListenerOrder = extensionForcedUser.getListenerOrder();
            this.listerOrder = forcedUserListenerOrder + 1;// this value must be larger than current ExtensionForcedUser.getListenerOrder()
            LOGGER4J.info("listnerOrder["
                    + this.listerOrder
                    + "] "
                    + (this.listerOrder>forcedUserListenerOrder?">":"<=")
                    + " forcedUserListnerOrder["
                    + forcedUserListenerOrder
                    + "]"
            );
        }
    }

    @Override
    public int getListenerOrder() {
        // TODO Auto-generated method stub
        return this.listerOrder;
    }

    @Override
    public void onHttpRequestSend(HttpMessage arg0, int arg1, HttpSender arg2) {
        try {
            // TODO Auto-generated method stub
            LOGGER4J.debug(
                    "called onHttpRequestSend :"
                            + debugprint_initiator(arg1)
                            + " URL["
                            + getURL(arg0)
                            + "]");

            // if (this.startedcon.isSenderFromStartedActiveScanners(arg2) ) {
            if (this.startedcon.isThreadFromStartedActiveScanners(Thread.currentThread().getId())) {
                // only call following methods when Scanner.start(Target) is called by
                // ExtensionActiveScanWrapper
                // forceUser set to null for disabling authentication.
                arg0.setRequestingUser(null);
                arg2.setUser(null);
                // disable redirect
                // arg2.setFollowRedirect(false);
                // run preMacro
                LOGGER4J.debug("beforemacro started threadid:" + Thread.currentThread().getId());
                beforemacroprovider.setParameters(this.startedcon, arg0, arg1, arg2);
                ThreadManagerProvider.getThreadManager().beginProcess(beforemacroprovider);
                LOGGER4J.debug("beforemacro end threadid:" + Thread.currentThread().getId());
                LOGGER4J.debug("Sender is originated from StartedActiveScan. senderid:" + arg2);
                ZapUtil.updateOriginalEncodedHttpMessage(arg0);
            } else {
                LOGGER4J.debug("onHttpRequestSend: no action. sender is not created by ExtensionActiveScanWrapper");
            }
        } finally {
        }
    }

    @Override
    public void onHttpResponseReceive(HttpMessage arg0, int arg1, HttpSender arg2) {
        // TODO Auto-generated method stub
        boolean mustCleanUp = false;
        try {
            LOGGER4J.debug(
                    "called onHttpResponseReceive :"
                            + debugprint_initiator(arg1)
                            + " URL["
                            + getURL(arg0)
                            + "]");
            if (this.startedcon.isThreadFromStartedActiveScanners(Thread.currentThread().getId())) {
                // only call following methods when Scanner.start(Target) is called by
                // ExtensionActiveScanWrapper
                // run postMacro
                mustCleanUp = true;
                LOGGER4J.debug("postmacro started threadid:" + Thread.currentThread().getId());
                postmacroprovider.setParameters(this.startedcon, arg0, arg1, arg2);
                ThreadManagerProvider.getThreadManager().beginProcess(postmacroprovider);
                LOGGER4J.debug("postmacro end threadid:" + Thread.currentThread().getId());
                LOGGER4J.debug(
                        "onHttpRequestReceive Sender is originated from StartedActiveScan. HttpSender:"
                                + arg2);
            } else {
                switch(arg1) {
                    // tracking cookies only in proxy/manual request.
                    case HttpSender.PROXY_INITIATOR:
                    case HttpSender.MANUAL_REQUEST_INITIATOR:
                        ParmGenMacroTraceProvider pmtProvider = this.startedcon.getPmtProvider();
                        pmtProvider.parseSetCookie(arg0);
                        break;
                    default:
                        break;
                }

                LOGGER4J.debug("onHttpResponseReceive: no action. sender is not created by ExtensionActiveScanWrapper");
            }
        } finally {
            if (mustCleanUp) {
                this.startedcon.removeThreadid(); // always keep clean.
                this.startedcon.removeUUID();
            }
        }
    }

    public String debugprint_initiator(int i) {
        String name = "unknown";
        switch (i) {
            case HttpSender.PROXY_INITIATOR:
                name = "PROXY_INITIATOR";
                break;
            case HttpSender.ACTIVE_SCANNER_INITIATOR:
                name = "ACTIVE_SCANNER_INITIATOR";
                break;
            case HttpSender.SPIDER_INITIATOR:
                name = "SPIDER_INITIATOR";
                break;
            case HttpSender.FUZZER_INITIATOR:
                name = "FUZZER_INITIATOR";
                break;
            case HttpSender.AUTHENTICATION_INITIATOR:
                name = "AUTHENTICATION_INITIATOR";
                break;
            case HttpSender.MANUAL_REQUEST_INITIATOR:
                name = "MANUAL_REQUEST_INITIATOR";
                break;
            case HttpSender.BEAN_SHELL_INITIATOR:
                name = "BEAN_SHELL_INITIATOR";
                break;
            case HttpSender.ACCESS_CONTROL_SCANNER_INITIATOR:
                name = "ACCESS_CONTROL_SCANNER_INITIATOR";
                break;
            case HttpSender.AJAX_SPIDER_INITIATOR:
                name = "AJAX_SPIDER_INITIATOR";
                break;
            case HttpSender.FORCED_BROWSE_INITIATOR:
                name = "FORCED_BROWSE_INITIATOR";
                break;
            case HttpSender.TOKEN_GENERATOR_INITIATOR:
                name = "TOKEN_GENERATOR_INITIATOR";
                break;
            default:
                name = "unknown";
                break;
        }
        return name;
    }

    public String getURL(HttpMessage hm) {
        String url = "";
        if (hm != null) {
            HttpRequestHeader hd = hm.getRequestHeader();
            url = hd.getURI().toString();
        }

        return url;
    }
}
