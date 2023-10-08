package org.zaproxy.zap.extension.automacrobuilder;

public interface InterfaceClientRequest {
    /**
     * send request with client dependent logic.
     *
     * @param prequest
     * @return
     */
    PRequestResponse clientRequest(ParmGenMacroTrace pmt, PRequest prequest);

    /**
     * reset(clear) dependent system's cookie manager(i.e. HttpState)
     */
    void resetCookieManager(ParmGenMacroTrace pmt);
}
