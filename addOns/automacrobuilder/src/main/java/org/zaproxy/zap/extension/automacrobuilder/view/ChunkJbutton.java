package org.zaproxy.zap.extension.automacrobuilder.view;

import javax.swing.*;

/**
 * JButton which stored arbitary data for displaying on StyleDocument
 *
 */
@SuppressWarnings({"unchecked", "serial"})
public class ChunkJbutton extends JButton implements InterfaceCompoStyleName{
    private int partno;
    private byte[] chunk;
    private String styleName;
    public ChunkJbutton(String styleName, int partno, byte[] chunk) {
        super();
        this.styleName = styleName;
        this.partno = partno;
        this.chunk = chunk;
    }

    public int getPartNo() {
        return this.partno;
    }

    public byte[] getChunk() {
        return this.chunk;
    }

    @Override
    public void setStyleName(String name) {
        this.styleName = name;
    }

    @Override
    public String getStyleName() {
        return this.styleName;
    }
}
