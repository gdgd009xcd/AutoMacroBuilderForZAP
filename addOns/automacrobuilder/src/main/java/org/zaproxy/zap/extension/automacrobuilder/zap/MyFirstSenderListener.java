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

import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.automacrobuilder.ThreadManagerProvider;
import org.zaproxy.zap.network.HttpSenderListener;

public class MyFirstSenderListener implements HttpSenderListener {

    private static final org.apache.logging.log4j.Logger LOGGER4J = org.apache.logging.log4j.LogManager.getLogger();
    private StartedActiveScanContainer startedcon = null;
    private BeforeMacroDoActionProvider beforemacroprovider = new BeforeMacroDoActionProvider();
    private PostMacroDoActionProvider postmacroprovider = new PostMacroDoActionProvider();

    MyFirstSenderListener(StartedActiveScanContainer startedcon) {
        this.startedcon = startedcon;
    }

    @Override
    public int getListenerOrder() {
        // TODO Auto-generated method stub
        // ExtensionForcedUser.getListenerOrder = 9998 + 1
        return 9999;
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
                // only call following methods when Scanner.start(Target) is called by ExtensionActiveScanWrapper
                // forceUser set to null for disabling authentication
                arg0.setRequestingUser(null);
                // run preMacro
                beforemacroprovider.setParameters(this.startedcon, arg0, arg1, arg2);
                ThreadManagerProvider.getThreadManager().beginProcess(beforemacroprovider);
                LOGGER4J.debug("Sender is originated from StartedActiveScan. senderid:" + arg2);
            } else {
                LOGGER4J.debug("sender is not created by ExtensionActiveScanWrapper");
            }
        } finally {
        }
    }

    @Override
    public void onHttpResponseReceive(HttpMessage arg0, int arg1, HttpSender arg2) {
        // TODO Auto-generated method stub
        try {
            LOGGER4J.debug(
                    "called onHttpResponseReceive :"
                            + debugprint_initiator(arg1)
                            + " URL["
                            + getURL(arg0)
                            + "]");
            if (this.startedcon.isThreadFromStartedActiveScanners(Thread.currentThread().getId())) {
                // only call following methods when Scanner.start(Target) is called by ExtensionActiveScanWrapper
                // run postMacro
                postmacroprovider.setParameters(this.startedcon, arg0, arg1, arg2);
                ThreadManagerProvider.getThreadManager().beginProcess(postmacroprovider);
                LOGGER4J.debug("onHttpRequestReceive Sender is originated from StartedActiveScan. scanid:" + arg2);
            }
        } finally {
            this.startedcon.removeThreadid(); // always keep clean.
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
            case HttpSender.CHECK_FOR_UPDATES_INITIATOR:
                name = "CHECK_FOR_UPDATES_INITIATOR";
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
