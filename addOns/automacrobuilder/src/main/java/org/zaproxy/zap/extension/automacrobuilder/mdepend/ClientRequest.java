package org.zaproxy.zap.extension.automacrobuilder.mdepend;

import static org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace.PMT_CURRENT_BEGIN;

import java.io.IOException;
import java.nio.charset.Charset;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.automacrobuilder.Encode;
import org.zaproxy.zap.extension.automacrobuilder.InterfaceClientRequest;
import org.zaproxy.zap.extension.automacrobuilder.PRequest;
import org.zaproxy.zap.extension.automacrobuilder.PRequestResponse;
import org.zaproxy.zap.extension.automacrobuilder.PResponse;
import org.zaproxy.zap.extension.automacrobuilder.ParmGen;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenBinUtil;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenMacroTrace;
import org.zaproxy.zap.extension.automacrobuilder.ParmVars;
import org.zaproxy.zap.extension.automacrobuilder.zap.ZapUtil;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;

public class ClientRequest implements InterfaceClientRequest {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    /**
     * send client HttpRequest
     *
     * @param request
     * @return
     */
    @Override
    public PRequestResponse clientRequest(ParmGenMacroTrace pmt, PRequest request) {
        PRequestResponse pqrs = null;
        if (request != null) {
            ParmGen pgen = new ParmGen(pmt);
            // set cookies & tokens in request
            PRequest updatedrequest = pgen.RunPRequest(request);
            if (updatedrequest != null) {
                request = updatedrequest;
            }

            Encode enc_iso8859_1 = Encode.ISO_8859_1;
            Charset charset_iso8859_1 = enc_iso8859_1.getIANACharset();
            String noresponse = "";
            byte[] byterequest = request.getByteMessage();
            String host = request.getHost();
            int port = request.getPort();
            boolean isSSL = request.isSSL();
            Encode _pageenc = request.getPageEnc();
            pmt.clearComments();
            pmt.setError(false);
            HttpMessage htmess = ZapUtil.getHttpMessage(request);

            try {
                // send message
                pmt.send(pmt.getSender(), htmess);
                HttpRequestHeader requestheader = htmess.getRequestHeader();
                HttpRequestBody requestbody = htmess.getRequestBody();
                ParmGenBinUtil requestbin = new ParmGenBinUtil(requestheader.toString().getBytes());
                requestbin.concat(requestbody.getBytes());
                HttpResponseHeader responseheader = htmess.getResponseHeader();
                HttpResponseBody responsebody = htmess.getResponseBody();
                ParmGenBinUtil responsebin =
                        new ParmGenBinUtil(responseheader.toString().getBytes());
                responsebin.concat(responsebody.getBytes());
                if (responsebin.length() < 1) {
                    responsebin.clear();
                    responsebin.concat(
                            new String("")
                                    .getBytes(charset_iso8859_1)); // not NULL, length zero bytes.
                }
                pqrs =
                        new PRequestResponse(
                                host,
                                port,
                                isSSL,
                                requestbin.getBytes(),
                                responsebin.getBytes(),
                                _pageenc);
                String url = pqrs.request.getURL();
                // parse response then extract tracking tokens
                int updtcnt = pgen.ResponseRun(url, pqrs.response);
                // parse response and extract set-Cookies.
                pmt.parseSetCookie(pqrs);
                if (pqrs != null) {
                    if (pqrs.response.getBodyContentLength() <= 0) {
                        noresponse = "\nNo Response(NULL)";
                    }
                    pqrs.setComments(pmt.getComments() + noresponse);
                    pqrs.setError(pmt.isError());
                }

            } catch (IOException e) {
                LOGGER4J.error("", e);
            }
        }
        return pqrs;
    }

    /**
     * set cookies & tokens in currentmessage
     *
     * @param currentmessage
     * @return
     */
    public HttpMessage startZapCurrentRequest(ParmGenMacroTrace pmt, HttpMessage currentmessage) {
        pmt.clearComments();
        pmt.setError(false);
        pmt.setState(PMT_CURRENT_BEGIN);
        ParmGen pgen = new ParmGen(pmt);

        PRequest prequest = ZapUtil.getPRequest(currentmessage, ParmVars.enc);

        PRequest retval = pgen.RunPRequest(prequest);

        if (retval != null) {
            HttpMessage newmessage = ZapUtil.getHttpMessage(retval);
            // update currentmessage contents
            currentmessage.setRequestHeader(newmessage.getRequestHeader());
            currentmessage.setRequestBody(newmessage.getRequestBody());
            currentmessage.setResponseHeader(newmessage.getResponseHeader());
            currentmessage.setResponseBody(newmessage.getResponseBody());
        }

        return currentmessage;
    }

    /**
     * parse response and extract tokens & cookies from currentrequest.
     *
     * @param pmt
     * @param currentmessage
     */
    public void postZapCurrentResponse(ParmGenMacroTrace pmt, HttpMessage currentmessage) {
        PRequestResponse prs = ZapUtil.getPRequestResponse(currentmessage, ParmVars.enc);

        String url = prs.request.getURL();
        LOGGER4J.debug("=====ResponseRun start====== status:" + prs.response.getStatus());
        ParmGen pgen = new ParmGen(pmt);
        int updtcnt = pgen.ResponseRun(url, prs.response);
        LOGGER4J.debug("=====ResponseRun end======");
        pmt.parseSetCookie(prs); // save Set-Cookie values into CookieStore.
        pmt.endAfterCurrentRequest(prs);
    }

    /**
     * update currentmessage's response with final postmacro response.
     *
     * @param pmt
     * @param currentmessage
     */
    public void updateCurrentResponseWithFinalResponse(
            ParmGenMacroTrace pmt, HttpMessage currentmessage) {
        if (pmt.isMBFinalResponse()) {
            PResponse finalresponse = pmt.getPostMacroPResponse();
            if (finalresponse != null) {

                try {
                    // update currentmessage's response
                    String responseheaders = finalresponse.getHeaderOnly();
                    byte[] responsebody = finalresponse.getBodyBytes();
                    currentmessage.setResponseHeader(responseheaders);
                    if (responsebody == null || responsebody.length < 1) {
                        responsebody = "".getBytes(); // not null zero length bytes.
                    }
                    currentmessage.setResponseBody(responsebody);
                } catch (HttpMalformedHeaderException e) {
                    LOGGER4J.error("", e);
                }
            }
        }
        pmt.macroEnded(); // all done.
    }
}
