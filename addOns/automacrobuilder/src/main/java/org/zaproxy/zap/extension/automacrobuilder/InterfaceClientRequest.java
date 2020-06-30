package org.zaproxy.zap.extension.automacrobuilder;

public interface InterfaceClientRequest {
    /**
     * send request with client dependent logic.
     *
     * @param prequest
     * @return
     */
    PRequestResponse clientRequest(ParmGenMacroTrace pmt, PRequest prequest);
}
