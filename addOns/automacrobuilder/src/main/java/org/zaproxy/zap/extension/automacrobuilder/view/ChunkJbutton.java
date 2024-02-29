package org.zaproxy.zap.extension.automacrobuilder.view;

import javax.swing.*;

/**
 * JButton which stored arbitary data for displaying on StyleDocument
 *
 */
@SuppressWarnings({"unchecked", "serial"})
public class ChunkJbutton extends JButton {
    private int partno;
    private byte[] chunk;
    public ChunkJbutton(int partno, byte[] chunk) {
        super();
        this.partno = partno;
        this.chunk = chunk;
    }

    public int getPartNo() {
        return this.partno;
    }

    public byte[] getChunk() {
        return this.chunk;
    }
}
