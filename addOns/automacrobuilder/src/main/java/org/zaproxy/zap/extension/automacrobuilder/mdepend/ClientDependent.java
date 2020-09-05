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
package org.zaproxy.zap.extension.automacrobuilder.mdepend;

import java.io.IOException;
import java.util.UUID;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpMethodHelper;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.automacrobuilder.PRequest;
import org.zaproxy.zap.extension.automacrobuilder.PRequestResponse;
import org.zaproxy.zap.extension.automacrobuilder.UUIDGenerator;

/** @author gdgd009xcd */
public class ClientDependent {

    public enum CLIENT_TYPE {
        BURPSUITE,
        ZAP
    }

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    public static final String LOG4JXML_DIR = Constant.getZapHome();

    private String comments = "";

    private boolean iserror = false;

    private UUID uuid = null;

    private HttpMessage currentmessage = null;

    // HttpMethodHelper has NO variable members. so, this instance can share any threads.
    private static HttpMethodHelper helper = new HttpMethodHelper();

    /**
     * get Client Type
     *
     * @return
     */
    public CLIENT_TYPE getClientType() {
        return ClientDependent.CLIENT_TYPE.ZAP;
    }

    /**
     * initialize this members.
     *
     * <p>members no need copy.
     */
    private void init() {
        comments = "";
        iserror = false;
        uuid = null;
        currentmessage = null;
    }

    public ClientDependent() {
        init();
        setUUID(UUIDGenerator.getUUID());
    }

    protected void burpSendToRepeater(
            String host, int port, boolean useHttps, byte[] messages, String tabtitle) {}

    protected void burpDoActiveScan(String host, int port, boolean useHttps, byte[] messages) {}

    protected void burpSendToIntruder(String host, int port, boolean useHttps, byte[] messages) {}

    protected PRequestResponse clientHttpRequest(PRequest request) {
        return null;
    }

    /**
     * Modified version runMethod. this method based on HttpSender class′s method No follow
     * redirects No authentication
     *
     * @param sender
     * @param msg
     * @return
     * @throws IOException
     */
    private HttpMethod runMethod(HttpSender sender, HttpMessage msg) throws IOException {
        HttpMethod method = null;

        // HttpMethodParams params = new HttpMethodParams();
        // int sotimeout = params.getSoTimeout();
        // LOGGER4J.debug("default timeout:" + sotimeout);

        method = helper.createRequestMethod(msg.getRequestHeader(), msg.getRequestBody());
        HttpMethodParams params = method.getParams();
        int sotimeout = params.getSoTimeout();
        LOGGER4J.debug("default timeout:" + sotimeout);

        // anyway, I decided to disable followRedirects
        method.setFollowRedirects(false);

        // ZAP: Use custom HttpState if needed

        sender.executeMethod(method, null);

        HttpMethodHelper.updateHttpRequestHeaderSent(msg.getRequestHeader(), method);

        return method;
    }

    /**
     * Send HttpMessage using specified sender. this method based on HttpSender class′s method No
     * follow redirects No authentication
     *
     * @param sender
     * @param msg
     * @throws IOException
     */
    public void send(HttpSender sender, HttpMessage msg) throws IOException {
        boolean isFollowRedirect = false;
        HttpMethod method = null;
        HttpResponseHeader resHeader = null;
        long starttime = 0;

        try {
            starttime = System.currentTimeMillis();
            method = runMethod(sender, msg);
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
            LOGGER4J.debug("release Connection and shutdown completed.");
            long endtime = System.currentTimeMillis();
            LOGGER4J.debug("runMethod lapse : " + (endtime - starttime) / 1000 + "sec.");
        }
    }

    public int getScanQuePercentage() {

        return -1;
    }

    protected void scanQueNull() {}

    /**
     * set UUID custom header unused function
     *
     * @param preq
     */
    protected void setUUID2CustomHeader(PRequest preq) {
        // preq.setUUID2CustomHeader(getUUID());
    }

    /**
     * set UUID unique that represents this instance
     *
     * @param uuid
     */
    private void setUUID(UUID uuid) {
        this.uuid = uuid;
    }

    /**
     * get UUID unique that represents this instance
     *
     * @return
     */
    public UUID getUUID() {
        return this.uuid;
    }

    public void clearComments() {
        comments = ""; // no null
    }

    public void addComments(String _v) {
        comments += _v + "\n";
    }

    void setComments(String _v) {
        comments = _v;
    }

    public String getComments() {
        return comments;
    }

    public void setError(boolean _b) {
        iserror = _b;
    }

    public boolean isError() {
        return iserror;
    }
}
