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
package org.zaproxy.zap.extension.automacrobuilder.mdepend;

import java.util.logging.Level;
import java.util.logging.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.automacrobuilder.Encode;
import org.zaproxy.zap.extension.automacrobuilder.InterfaceClientDependantMessage;
import org.zaproxy.zap.extension.automacrobuilder.ParmGenBinUtil;

/** @author gdgd009xcd */
public class ClientDependMessageContainer
        implements InterfaceClientDependantMessage<HistoryReference> {

    private HistoryReference href = null;

    private static org.apache.logging.log4j.Logger logger4j =
            org.apache.logging.log4j.LogManager.getLogger();

    public ClientDependMessageContainer(HistoryReference href) {
        setClientDependMessage(href);
    }

    /**
     * Get HistoryReference of this RequestResponse
     *
     * @return HistoryReference
     */
    @Override
    public HistoryReference getClientDpendMessage() {
        return this.href;
    }

    /**
     * Set HistoryReference of this RequestResponse
     *
     * @param t HistoryReference
     */
    @Override
    public final void setClientDependMessage(HistoryReference t) {
        this.href = t;
    }

    @Override
    public String getHost() {
        try {
            return this.href.getHttpMessage().getRequestHeader().getHostName();
        } catch (HttpMalformedHeaderException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        } catch (DatabaseException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        return "";
    }

    @Override
    public int getPort() {
        try {
            return this.href.getHttpMessage().getRequestHeader().getHostPort();
        } catch (HttpMalformedHeaderException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        } catch (DatabaseException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        return -1;
    }

    @Override
    public boolean isSSL() {
        try {
            return this.href.getHttpMessage().getRequestHeader().isSecure();
        } catch (HttpMalformedHeaderException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        } catch (DatabaseException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        return false;
    }

    @Override
    public byte[] getRequestByte() {

        try {
            String reqheader =
                    this.href
                            .getHttpMessage()
                            .getRequestHeader()
                            .toString(); // getPrimeHeader() + mLineDelimiter + mMsgHeader +
            // mLineDelimiter;
            // get body bytes with applying properly decoding which is based on Content-Encoding
            byte[] bodybin = this.href.getHttpMessage().getRequestBody().getContent();
            ParmGenBinUtil pbinutil = new ParmGenBinUtil(reqheader.getBytes());
            pbinutil.concat(bodybin);
            return pbinutil.getBytes();
        } catch (Exception ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public byte[] getResponseByte() {
        try {
            String resheader =
                    this.href
                            .getHttpMessage()
                            .getResponseHeader()
                            .toString(); // getPrimeHeader() + mLineDelimiter + mMsgHeader +
            // mLineDelimiter;
            // get body bytes with applying properly decoding which is base on Content-Encoding
            byte[] bodybin = this.href.getHttpMessage().getResponseBody().getContent();
            ParmGenBinUtil pbinutil = new ParmGenBinUtil(resheader.getBytes());
            pbinutil.concat(bodybin);
            return pbinutil.getBytes();
        } catch (HttpMalformedHeaderException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        } catch (DatabaseException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public Encode getRequestEncode() {
        String charsetname;
        try {
            charsetname = this.href.getHttpMessage().getRequestHeader().getCharset();
            if (Encode.isExistEnc(charsetname)) {
                return Encode.getEnum(charsetname);
            }
        } catch (HttpMalformedHeaderException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        } catch (DatabaseException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        return null;
    }

    @Override
    public Encode getResponseEncode() {
        String charsetname;
        try {
            charsetname = this.href.getHttpMessage().getResponseHeader().getCharset();
            if (Encode.isExistEnc(charsetname)) {
                return Encode.getEnum(charsetname);
            }
        } catch (HttpMalformedHeaderException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        } catch (DatabaseException ex) {
            Logger.getLogger(ClientDependMessageContainer.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
