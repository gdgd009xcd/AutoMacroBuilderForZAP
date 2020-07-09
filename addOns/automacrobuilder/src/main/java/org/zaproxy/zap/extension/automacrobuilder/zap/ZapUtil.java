package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.nio.charset.Charset;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.automacrobuilder.Encode;
import org.zaproxy.zap.extension.automacrobuilder.PRequest;
import org.zaproxy.zap.extension.automacrobuilder.PRequestResponse;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenBinUtil;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.StyledDocumentWithChunk;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;

public class ZapUtil {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    /**
     * Get HttpMessage from PRequestResponse
     *
     * @param ppr PRequestResponse
     * @return HttpMessage
     */
    public static HttpMessage getHttpMessage(PRequestResponse ppr) {

        HttpMessage htmess = null;
        if (ppr != null) {
            String reqheader = ppr.request.getHeaderOnly();
            byte[] reqBody = ppr.request.getBodyBytes();
            String resheader = ppr.response.getHeaderOnly();
            byte[] resBody = ppr.response.getBodyBytes();
            if (LOGGER4J.isDebugEnabled()) {
                if (reqheader != null) {
                    // LOGGER4J.debug(reqheader);
                }
                LOGGER4J.debug("reqbody length:" + (reqBody != null ? reqBody.length : 0));
            }
            try {
                htmess = new HttpMessage(reqheader, reqBody, resheader, resBody);
            } catch (HttpMalformedHeaderException e) {
                LOGGER4J.error("", e);
            }
        }

        return htmess;
    }

    /**
     * Get HttpMessage from PRequest
     *
     * @param preq
     * @return
     */
    public static HttpMessage getHttpMessage(PRequest preq) {
        HttpMessage htmess = null;

        String reqhstr = preq.getHeaderOnly();
        byte[] reqBody = preq.getBodyBytes();
        boolean isSSL = preq.isSSL();

        try {
            HttpRequestHeader httpReqHeader = new HttpRequestHeader(reqhstr, isSSL);
            HttpRequestBody mReqBody = new HttpRequestBody();
            mReqBody.setBody(preq.getBodyBytes());
            // getCharset return may be null. this function simply get request's content-type
            // header's value.
            // setCharset function may be set null value. this function also simply set parameter as
            // is.
            mReqBody.setCharset(httpReqHeader.getCharset());
            htmess = new HttpMessage(httpReqHeader, mReqBody);
        } catch (HttpMalformedHeaderException e) {
            LOGGER4J.error("reqhstr:" + reqhstr, e);
        }

        return htmess;
    }

    /**
     * Get Current Selected HttpMessage in MacroBuilder's RequestList.
     *
     * @param mbui
     * @return null or HttpMessage
     */
    public static HttpMessage getCurrentHttpMessage(MacroBuilderUI mbui) {
        int pos = mbui.getCurrentSelectedRequestIndex();
        if (pos > -1) {
            ParmGenMacroTrace pmt = mbui.getParmGenMacroTrace();
            pmt.setCurrentRequest(pos);
            PRequestResponse prr = pmt.getCurrentRequestResponse();
            StyledDocumentWithChunk doc = mbui.getMacroRequestStyledDocument();
            if (doc != null) {
                PRequest prequest = doc.reBuildPRequestFromDocText();
                if (prequest != null) {
                    return getHttpMessage(prequest);
                }
            }
        }
        return null;
    }

    /**
     * Get PRequstResponse from HttpMessage
     *
     * @param htmess
     * @param pageenc
     * @return
     */
    public static PRequestResponse getPRequestResponse(HttpMessage htmess, Encode pageenc) {
        HttpRequestHeader requestheader = htmess.getRequestHeader();
        HttpRequestBody requestbody = htmess.getRequestBody();
        ParmGenBinUtil requestbin = new ParmGenBinUtil(requestheader.toString().getBytes());
        requestbin.concat(requestbody.getBytes());
        HttpResponseHeader responseheader = htmess.getResponseHeader();
        HttpResponseBody responsebody = htmess.getResponseBody();
        ParmGenBinUtil responsebin = new ParmGenBinUtil(responseheader.toString().getBytes());
        responsebin.concat(responsebody.getBytes());
        if (responsebin.length() < 1) {
            responsebin.clear();
            Encode enc_iso8859_1 = Encode.ISO_8859_1;
            Charset charset_iso8859_1 = enc_iso8859_1.getIANACharset();
            responsebin.concat(
                    new String("").getBytes(charset_iso8859_1)); // not NULL, length zero bytes.
        }
        String host = requestheader.getHostName();
        int port = requestheader.getHostPort();
        boolean isSSL = requestheader.isSecure();
        return new PRequestResponse(
                host, port, isSSL, requestbin.getBytes(), responsebin.getBytes(), pageenc);
    }

    /**
     * Get PRequest from HttpMessage
     *
     * @param htmess
     * @param pageenc
     * @return
     */
    public static PRequest getPRequest(HttpMessage htmess, Encode pageenc) {
        HttpRequestHeader requestheader = htmess.getRequestHeader();
        HttpRequestBody requestbody = htmess.getRequestBody();
        ParmGenBinUtil requestbin = new ParmGenBinUtil(requestheader.toString().getBytes());
        requestbin.concat(requestbody.getBytes());
        String host = requestheader.getHostName();
        int port = requestheader.getHostPort();
        boolean isSSL = requestheader.isSecure();
        return new PRequest(host, port, isSSL, requestbin.getBytes(), pageenc);
    }
}
