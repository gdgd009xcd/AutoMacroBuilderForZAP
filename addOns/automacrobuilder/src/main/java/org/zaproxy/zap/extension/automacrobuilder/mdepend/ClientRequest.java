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
import org.zaproxy.zap.extension.automacrobuilder.ParseHttpContentType;
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
            pmt.clearComments();
            pmt.setError(false);

            int currentStepNo = pmt.getStepNo();

            // set cookies & tokens in request
            PRequest updatedrequest = pgen.RunPRequest(request);
            if (updatedrequest != null) {
                request = updatedrequest;
            }

            Encode enc_iso8859_1 = Encode.ISO_8859_1;
            Charset charset_iso8859_1 = enc_iso8859_1.getIANACharset();
            String noresponse = "";
            String host = request.getHost();
            int port = request.getPort();
            boolean isSSL = request.isSSL();

            HttpMessage htmess = ZapUtil.getHttpMessageFromPRequest(request);

            try {
                // send message
                pmt.send(pmt.getSender(), htmess);
                LOGGER4J.debug("STEP[" + pmt.getStepNo() + "] send URL:" + htmess.getRequestHeader().getURI());
                HttpRequestHeader requestheader = htmess.getRequestHeader();
                HttpRequestBody requestbody = htmess.getRequestBody();

                ParmGenBinUtil requestbin = new ParmGenBinUtil(requestheader.toString().getBytes());
                //requestbin.concat(requestbody.getBytes());
                // must use getContent method which can get properly decoded value.
                requestbin.concat(requestbody.getContent());
                HttpResponseHeader responseheader = htmess.getResponseHeader();
                HttpResponseBody responsebody = htmess.getResponseBody();
                String responseHeaderString =
                        responseheader
                                .toString(); // response header1<CR><LF>...headerN<CR><LF><CR><LF>
                Encode responseEncode = pmt.getSequenceEncode();
                ParseHttpContentType responseHttpContentType =
                        new ParseHttpContentType(responseHeaderString);
                if (responseHttpContentType.isResponse()
                        && responseHttpContentType.hasContentTypeHeader()) {
                    responseEncode = Encode.getEnum(responseHttpContentType.getCharSetName());
                }
                ParmGenBinUtil responsebin = new ParmGenBinUtil(responseHeaderString.getBytes());
                //responsebin.concat(responsebody.getBytes());
                // must use getContent method which get body bytes with applying properly decoding which is based on Content-Encoding
                responsebin.concat(responsebody.getContent());
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
                                request.getPageEnc(),
                                responseEncode);
                String url = pqrs.request.getURL();
                // parse response then extract tracking tokens
                int updtcnt = pgen.ResponseRun(url, pqrs);
                // parse response and extract set-Cookies.
                pmt.parseSetCookie(pqrs);
                if (pqrs != null) {
                    if (pqrs.response.getBodyContentLength() <= 0) {
                        noresponse = "\nNo Response(NULL)";
                    }
                    pqrs.setComments(pmt.getComments() + noresponse);
                    if (currentStepNo != 0 || !pmt.isCacheNull()) {
                        pqrs.setError(pmt.isError());
                    }
                }
            } catch (IOException e) {
                LOGGER4J.error("", e);
            }
        }

        return pqrs;
    }

    public void resetCookieManager(ParmGenMacroTrace pmt){
        pmt.resetZapCookieState(pmt.getSender());
    }

    /**
     * set cookies & tokens in currentmessage
     *
     * @param currentmessage
     * @return
     */
    public HttpMessage startZapCurrentRequest(ParmGenMacroTrace pmt, HttpMessage currentmessage) {
        LOGGER4J.debug("startZapCurrentRequest is Called.");
        pmt.clearComments();
        pmt.setError(false);
        pmt.setState(PMT_CURRENT_BEGIN);
        ParmGen pgen = new ParmGen(pmt);

        PRequest prequest = ZapUtil.getPRequest(currentmessage, pmt.getLastResponseEncode());

        pmt.setURIOfRequestIsModified(isURIOfRequestIsModified(pmt, prequest));
        PRequest retval = pgen.RunPRequest(prequest);

        if (retval != null) {
            HttpMessage newmessage = ZapUtil.getHttpMessageFromPRequest(retval);
            LOGGER4J.debug("ZapUtil.getHttpMessage URL[" + newmessage.getRequestHeader().getURI().toString() + "]");
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
        LOGGER4J.info("STEP[" + pmt.getStepNo() + "] current send URL:" + currentmessage.getRequestHeader().getURI());
        PRequestResponse prs = ZapUtil.getPRequestResponse(currentmessage, pmt.getSequenceEncode());

        String url = prs.request.getURL();
        LOGGER4J.debug("=====ResponseRun start====== status:" + prs.response.getStatus());
        ParmGen pgen = new ParmGen(pmt);
        int updtcnt = pgen.ResponseRun(url, prs);
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
        LOGGER4J.debug("isURIOfRequestIsModified:"+ (pmt.isURIOfRequestIsModified()?"true":"false"));
        if (pmt.isCBFinalResponse() && !pmt.isURIOfRequestIsModified()) {
            PResponse finalresponse = pmt.getPostMessagePResponse();
            if (finalresponse != null) {
                try {
                    // update currentmessage's response
                    String responseheaders = finalresponse.getHeaderOnly();
                    byte[] responsebody = finalresponse.getBodyBytes();
                    currentmessage.setResponseHeader(responseheaders);
                    if (responsebody == null || responsebody.length < 1) {
                        responsebody = "".getBytes(); // not null zero length bytes.
                    }
                    //currentmessage.setResponseBody(responsebody);
                    // set body bytes with applying properly encoding which is based on Content-Encoding
                    currentmessage.getResponseBody().setContent(responsebody);
                } catch (HttpMalformedHeaderException e) {
                    LOGGER4J.error("", e);
                }
            }
        }
        pmt.macroEnded(); // all done.
    }

    /**
     * check URI of prequest is modified by ActiveScan
     *
     * @param prequest
     * @return true - modified. false - original
     */
    private boolean isURIOfRequestIsModified(ParmGenMacroTrace pmt, PRequest prequest) {
        PRequestResponse original = pmt.getCurrentOriginalRequest();
        PRequest originalPRequest =  original.request;

        String URI_no_query = prequest.getURIWithoutQueryPart();
        String originalURI_no_query = originalPRequest.getURIWithoutQueryPart();
        LOGGER4J.debug("URI[" + URI_no_query + "] original URI[" + originalURI_no_query + "]");
        if (URI_no_query != null) {
            if (URI_no_query.equals(originalURI_no_query)) {
                return false;
            }
        } else return URI_no_query != originalURI_no_query;
        return true;
    }
}
