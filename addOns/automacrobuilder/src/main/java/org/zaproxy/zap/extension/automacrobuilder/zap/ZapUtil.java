package org.zaproxy.zap.extension.automacrobuilder.zap;

import java.lang.reflect.Method;
import java.nio.charset.Charset;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.automacrobuilder.*;
import org.zaproxy.zap.extension.automacrobuilder.view.StyledDocumentWithChunk;
import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;

import javax.swing.*;

public class ZapUtil {

    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();


    private static Extension extensionCustomActive = null;
    private static ClassLoader classLoaderCustomActive = null;
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
     * get PRequest from StyledDocumentWithChunk doc
     *
     * @param doc
     * @return
     */
    public static HttpMessage getHttpMessage(StyledDocumentWithChunk doc) {
        PRequest preq = doc.reBuildPRequestFromDocTextAndChunks();
        if (preq != null) {
            return getHttpMessage(preq);
        }
        return null;
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
            // set PRequest Encoding Charset to request Body Charset
            mReqBody.setCharset(preq.getPageEnc().getIANACharsetName());
            htmess = new HttpMessage(httpReqHeader, mReqBody);
        } catch (HttpMalformedHeaderException e) {
            LOGGER4J.error("reqhstr:" + reqhstr, e);
        }

        return htmess;
    }

    /**
     * Get PRequest from Contents of MacroRequest in mbui
     *
     * @param mbui
     * @return null or PRequest
     */
    public static PRequest getPRequestFromMacroRequest(MacroBuilderUI mbui) {
        int selectedTabIndex = mbui.getSelectedTabIndexOfMacroRequestList();
        int pos = mbui.getRequestJListSelectedIndexAtTabIndex(selectedTabIndex);
        ParmGenMacroTrace pmt = mbui.getParmGenMacroTraceAtTabIndex(selectedTabIndex);

        if (pos > -1 && pmt != null) {

            pmt.setCurrentRequest(pos);

            StyledDocumentWithChunk doc = mbui.getStyledDocumentOfSelectedMessageRequest();
            if (doc != null) {
                PRequestResponse prr = pmt.getRequestResponseCurrentList(pos);
                PRequest newrequest = doc.reBuildPRequestFromDocTextAndChunks();
                prr.updateRequest(newrequest.clone());
                return newrequest;
            }
        }
        return null;
    }

    /**
     * Get PRequstResponse from HttpMessage
     *
     * @param htmess
     * @param sequenceEncode
     * @return
     */
    public static PRequestResponse getPRequestResponse(HttpMessage htmess, Encode sequenceEncode) {
        HttpRequestHeader requestheader = htmess.getRequestHeader();
        HttpRequestBody requestbody = htmess.getRequestBody();
        Encode requestBodyEncode = Encode.getEnum(requestbody.getCharset());
        if (requestBodyEncode == null) {
            requestBodyEncode = sequenceEncode;
        }
        ParmGenBinUtil requestbin = new ParmGenBinUtil(requestheader.toString().getBytes());
        requestbin.concat(requestbody.getBytes());
        HttpResponseHeader responseheader = htmess.getResponseHeader();
        HttpResponseBody responsebody = htmess.getResponseBody();
        Encode responseBodyEncode = Encode.getEnum(responsebody.getCharset());
        if (responseBodyEncode == null) {
            responseBodyEncode = sequenceEncode;
        }
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
                host,
                port,
                isSSL,
                requestbin.getBytes(),
                responsebin.getBytes(),
                requestBodyEncode,
                responseBodyEncode);
    }

    /**
     * Get PRequest from HttpMessage
     *
     * @param htmess
     * @return
     */
    public static PRequest getPRequest(HttpMessage htmess, Encode lastResponseEncode) {
        HttpRequestHeader requestheader = htmess.getRequestHeader();
        HttpRequestBody requestbody = htmess.getRequestBody();
        Encode requestBodyEncode = lastResponseEncode;

        LOGGER4J.debug(
                "HttpMessage Charset["
                        + requestbody.getCharset()
                        + "] lastResponseEncode["
                        + lastResponseEncode.getIANACharsetName()
                        + "]");
        ParmGenBinUtil requestbin = new ParmGenBinUtil(requestheader.toString().getBytes());
        requestbin.concat(requestbody.getBytes());
        String host = requestheader.getHostName();
        int port = requestheader.getHostPort();
        boolean isSSL = requestheader.isSecure();
        return new PRequest(host, port, isSSL, requestbin.getBytes(), requestBodyEncode);
    }

    /**
     * get integer value from parsed String value<br>
     * if String value is null or empty or non integer value,<br>
     * then return defaultInt value.
     *
     * @param valString
     * @param defaultInt
     * @return
     */
    public static int parseInt(String valString, int defaultInt) {
        int resultInt = defaultInt;
        if (valString != null && !valString.isEmpty()) {
            try {
                resultInt = Integer.parseInt(valString);
            } catch (NumberFormatException e) {
                resultInt = defaultInt;
            }
        }
        return resultInt;
    }

    /**
     * get String representation of int val<br>
     * if val < 0 then this method return defaultString
     *
     * @param val
     * @param defaultString
     * @return
     */
    public static String int2String(int val, String defaultString) {
        return val >= 0 ? Integer.toString(val) : defaultString;
    }

    protected static Extension getExtensionAscanRules() {
        if (ZapUtil.extensionCustomActive == null) {
            ZapUtil.extensionCustomActive = Control.getSingleton()
                    .getExtensionLoader()
                    .getExtension("ExtensionCustomActiveScanRules");
        }
        if (ZapUtil.extensionCustomActive != null) {
            if (!ZapUtil.extensionCustomActive.isEnabled()) {
                ZapUtil.extensionCustomActive = null;
                ZapUtil.classLoaderCustomActive = null;
            }
        }
        return ZapUtil.extensionCustomActive;
    }
    private static ClassLoader getClassLoaderCustomActiveScan() {
        Extension extension = getExtensionAscanRules();
        if (ZapUtil.classLoaderCustomActive == null) {
            if (extension != null) {
                AddOn addon = extension.getAddOn();
                if (addon != null) {
                    try {
                        ZapUtil.classLoaderCustomActive = addon.getClassLoader();
                        return ZapUtil.classLoaderCustomActive;
                    } catch (Exception ex) {
                        LOGGER4J.error(ex.getMessage(), ex);
                    }
                    return null;
                }
            } else {
                LOGGER4J.debug("extension not found.");
            }
        }
        return ZapUtil.classLoaderCustomActive;
    }

    public static boolean callCustomActiveScanMethod(Object object, String packageName, String methodName, Class<?>[] clazzArray, Object[] objectArray) {

        String examplePackageName = "org.zaproxy.zap.extension.customactivescan.HttpMessageWithLCSResponse";

        Object[] exampleargument =  new Object[]{
          123, "a"
        };

        Class<?>[] exampleClazz = {
                Integer.class, String.class
        };

        boolean called = false;

        ClassLoader addonClassLoader = getClassLoaderCustomActiveScan();
        if (addonClassLoader != null) {
            try {
                Class<?> cls = Class.forName(packageName, true, addonClassLoader);
                LOGGER4J.debug("loaded class:" + cls.getName());
                if (cls.isAssignableFrom(object.getClass())) {
                    if (clazzArray == null || objectArray == null || clazzArray.length == 0 || objectArray.length == 0) {
                        Method method = object.getClass().getMethod(methodName);
                        method.invoke(object);
                        called = true;
                    } else {
                        Method method = object.getClass().getMethod(methodName, clazzArray);
                        method.invoke(object, objectArray);
                        LOGGER4J.debug("invoked.cls:" + cls.getName() + " method:" + methodName);
                        called = true;
                    }
                } else {
                    LOGGER4J.debug("different.cls:" + cls.getName() + " object:" + object.getClass().getName());
                }

            } catch (Exception ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
        }
        return called;
    }

    public static <T> T callCustomActiveScanMethodReturner(Class<T> returnClass, Object object, String packageName, String methodName, Class<?>[] clazzArray, Object[] objectArray) {

        T returnValue = null;
        String examplePackageName = "org.zaproxy.zap.extension.customactivescan.HttpMessageWithLCSResponse";

        Object[] exampleargument =  new Object[]{
                123, "a"
        };

        Class<?>[] exampleClazz = {
                Integer.class, String.class
        };

        boolean called = false;

        ClassLoader addonClassLoader = getClassLoaderCustomActiveScan();
        if (addonClassLoader != null) {
            try {
                Class<?> cls = Class.forName(packageName, true, addonClassLoader);
                LOGGER4J.debug("loaded class:" + cls.getName());
                if (cls.isAssignableFrom(object.getClass())) {
                    if (clazzArray == null || objectArray == null || clazzArray.length == 0 || objectArray.length == 0) {
                        Method method = object.getClass().getMethod(methodName);
                        returnValue = CastUtils.castToType(returnClass, method.invoke(object));
                        called = true;
                    } else {
                        Method method = object.getClass().getMethod(methodName, clazzArray);
                        returnValue =CastUtils.castToType(returnClass, method.invoke(object, objectArray));
                        LOGGER4J.debug("invoked.cls:" + cls.getName() + " method:" + methodName);
                        called = true;
                    }
                } else {
                    LOGGER4J.debug("different.cls:" + cls.getName() + " object:" + object.getClass().getName());
                }

            } catch (Exception ex) {
                returnValue = null;
                LOGGER4J.error(ex.getMessage(), ex);
            }
        }
        return returnValue;
    }
    public static void SwingInvokeLaterIfNeeded(Runnable runnable) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(runnable);
        } else {
            runnable.run();
        }
    }
}
