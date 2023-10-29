/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder;

import java.util.logging.Level;
import java.util.logging.Logger;

public class RequestChunk implements DeepClone {
    public enum CHUNKTYPE {
        REQUESTHEADER, // HEADER<CR><LF>HEADER<CRLF><CRLF>
        BOUNDARY, // -----------------------------178155009418426923672012858312<CR><LF>
        BOUNDARYHEADER, // Content-Disposition: form-data; name="imgfile";
        // filename="romischenreiches.jpg"<CR><LF>Content-Type:
        // image/jpeg<CR><LF><CR><LF>
        CONTENTS, // [binary](without CONTENTSEND)
        CONTENTSIMG, // image (without CONTENTSEND)
        CONTENTSEND, // <CR><LF>
        LASTBOUNDARY, // -----------------------------178155009418426923672012858312--<CR><LF>
    };

    CHUNKTYPE ctype;
    byte[] data;
    int partno;

    RequestChunk(CHUNKTYPE ctype, byte[] data, int partno) {
        this.ctype = ctype;
        this.data = data;
        this.partno = partno;
    }

    /**
     * Get getChunkType
     *
     * @return
     */
    public CHUNKTYPE getChunkType() {
        return this.ctype;
    }

    public void setChunkType(CHUNKTYPE c) {
        this.ctype = c;
    }

    /**
     * Get byte data
     *
     * @return
     */
    public byte[] getBytes() {
        return this.data;
    }

    public void setByte(byte[] data) {
        this.data = data;
    }

    /**
     * multi-part number from 0
     *
     * @return
     */
    public int getPartNo() {
        return this.partno;
    }

    public RequestChunk clone() {
        try {
            RequestChunk nobj = (RequestChunk) super.clone();
            byte[] obytes = this.data;
            if (obytes != null) {
                if (obytes.length == 0) {
                    nobj.data = "".getBytes();
                } else {
                    nobj.data = new byte[obytes.length];
                    System.arraycopy(obytes, 0, nobj.data, 0, obytes.length);
                }
            } else {
                nobj.data = null;
            }
            return nobj;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(PRequest.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
