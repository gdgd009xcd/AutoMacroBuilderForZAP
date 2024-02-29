package org.zaproxy.zap.extension.automacrobuilder.view;

public class PlaceHolderStyleChunk extends PlaceHolderStyle {

    private int partNo;
    private byte[] chunkByte;

    public PlaceHolderStyleChunk(int pos, String styleName, int partNo, byte[] chunkByte) {
        super(pos, styleName);
        this.partNo = partNo;
        this.chunkByte = chunkByte;
    }

    public int getPartNo() {
        return partNo;
    }

    public byte[] getChunkByte() {
        return this.chunkByte;
    }


}
