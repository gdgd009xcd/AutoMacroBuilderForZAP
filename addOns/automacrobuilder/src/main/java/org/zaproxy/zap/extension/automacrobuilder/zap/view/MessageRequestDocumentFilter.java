package org.zaproxy.zap.extension.automacrobuilder.zap.view;

import org.zaproxy.zap.extension.automacrobuilder.StartEndPosition;
import org.zaproxy.zap.extension.automacrobuilder.view.StyledDocumentWithChunk;
import org.zaproxy.zap.extension.automacrobuilder.zap.DecoderTag;

import javax.swing.text.AttributeSet;
import javax.swing.text.Document;
import javax.swing.text.DocumentFilter;
import java.util.ArrayList;
import java.util.List;

public class MessageRequestDocumentFilter extends DocumentFilter {
    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private StyledDocumentWithChunk doc;
    public MessageRequestDocumentFilter(StyledDocumentWithChunk doc) {
        this.doc = doc;
    }


    @Override
    public void remove(DocumentFilter.FilterBypass fb, int offset, int len) {
        if(!doc.getDocumentFilterMasked()) {
            try {
                LOGGER4J.debug("remove is called offset,len=" + offset + "," + len + " doclength=" + fb.getDocument().getLength());
                Document doc = fb.getDocument();
                int docLength = doc.getLength();
                String requestText = doc.getText(0, docLength);
                List<StartEndPosition> startEndPositions = DecoderTag.getDecodeTagList(requestText);
                int start = offset;
                int end = offset + len;
                for (StartEndPosition startEndPosition : startEndPositions) {
                    //   -- same
                    //   --
                    //   -- overlap
                    //  ----
                    //    -- between
                    //   --
                    //    --
                    if (start <= startEndPosition.start && end >= startEndPosition.end
                            || start > startEndPosition.start && start < startEndPosition.end
                            || end > startEndPosition.start && end < startEndPosition.end
                    ) {
                        LOGGER4J.debug("BEEP start,end=" + start + "," + end + " StartPos,EndPos=" + startEndPosition.start + "," + startEndPosition.end);
                        java.awt.Toolkit.getDefaultToolkit().beep();
                        return;
                    } else {
                        LOGGER4J.debug("start,end=" + start + "," + end + " StartPos,EndPos=" + startEndPosition.start + "," + startEndPosition.end);
                    }
                }

            } catch (Exception ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
        } else {
            LOGGER4J.debug("masked remove");
        }
        try {
            fb.remove(offset, len);
        } catch (Exception ex2) {
            LOGGER4J.error(ex2.getMessage(), ex2);
        }
    }

    @Override
    public void insertString(DocumentFilter.FilterBypass fb, int offset, String string, AttributeSet attr){
        List<StartEndPosition> decodedAreaStartEndPositions = new ArrayList<>();
        if (!doc.getDocumentFilterMasked()) {
            LOGGER4J.debug("insertString is called offset=" + offset + " doclength=" + fb.getDocument().getLength());
            try {
                Document doc = fb.getDocument();
                int docLength = doc.getLength();
                String requestText = doc.getText(0, docLength);
                List<StartEndPosition> decodeTagStartEndPositions = DecoderTag.getDecodeTagList(requestText);

                int areaStart = -1;
                for (StartEndPosition decodeTagStartEndPosition : decodeTagStartEndPositions) {
                    LOGGER4J.debug("insertString start,end=" + decodeTagStartEndPosition.start + "," + decodeTagStartEndPosition.end
                            + " string[" + decodeTagStartEndPosition.value + "]");
                    if (areaStart != -1) {
                        StartEndPosition decodedAreaStartEndPosition = new StartEndPosition(areaStart, decodeTagStartEndPosition.start);
                        decodedAreaStartEndPositions.add(decodedAreaStartEndPosition);
                    }
                    if (offset > decodeTagStartEndPosition.start && offset < decodeTagStartEndPosition.end) {
                        java.awt.Toolkit.getDefaultToolkit().beep();
                        return;
                    }
                    areaStart = decodeTagStartEndPosition.end;
                }

            } catch (Exception ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
        } else {
            LOGGER4J.debug("masked insertString");
        }
        try {
            if (!doc.getDocumentFilterMasked()) {
                for (StartEndPosition decodedAreaStartEndPosition : decodedAreaStartEndPositions) {
                    if (offset >= decodedAreaStartEndPosition.start && offset <= decodedAreaStartEndPosition.end) {
                        if (!DecoderTag.isDecodedTaggedString(string)) {
                            string = DecoderTag.removeDecodeTag(string);
                        }
                        LOGGER4J.debug("insertString string[" + string + "]");
                        break;
                    }
                }
            }
            fb.insertString(offset, string, attr);
        } catch (Exception ex2) {
            LOGGER4J.error(ex2.getMessage(), ex2);
        }
    }

    @Override
    public void replace(DocumentFilter.FilterBypass fb, int offset, int length, String text, AttributeSet attr) {
        LOGGER4J.debug("replace is called offset,length=" + offset + "," + length + " text[" + text + "] doclength=" + fb.getDocument().getLength() );
        List<StartEndPosition> decodedAreaStartEndPositions = new ArrayList<>();
        if (!doc.getDocumentFilterMasked()) {
            try {
                Document doc = fb.getDocument();
                int docLength = doc.getLength();
                String requestText = doc.getText(0, docLength);
                List<StartEndPosition> decodeTagStartEndPositions = DecoderTag.getDecodeTagList(requestText);
                int start = offset;
                int end = offset + length;
                int areaStart = -1;
                for (StartEndPosition decodeTagStartEndPosition : decodeTagStartEndPositions) {
                    LOGGER4J.debug("start,end=" + decodeTagStartEndPosition.start + "," + decodeTagStartEndPosition.end
                            + " string[" + decodeTagStartEndPosition.value + "]");
                    if (areaStart != -1) {
                        StartEndPosition decodedAreaStartEndPosition = new StartEndPosition(areaStart, decodeTagStartEndPosition.start);
                        decodedAreaStartEndPositions.add(decodedAreaStartEndPosition);
                    }
                    if (start <= decodeTagStartEndPosition.start && end >= decodeTagStartEndPosition.end
                            || start > decodeTagStartEndPosition.start && start < decodeTagStartEndPosition.end
                            || end > decodeTagStartEndPosition.start && end < decodeTagStartEndPosition.end
                    ) {
                        java.awt.Toolkit.getDefaultToolkit().beep();
                        return;
                    }
                    areaStart = decodeTagStartEndPosition.end;
                }
            } catch (Exception ex) {
                LOGGER4J.error(ex.getMessage(), ex);
            }
        } else {
            LOGGER4J.debug("masked replace");
        }
        try {
            if (!doc.getDocumentFilterMasked()) {
                for (StartEndPosition decodedAreaStartEndPosition : decodedAreaStartEndPositions) {
                    int start = offset;
                    int end = offset + length;
                    if (start >= decodedAreaStartEndPosition.start && end <= decodedAreaStartEndPosition.end) {
                        if (!DecoderTag.isDecodedTaggedString(text)) {
                            text = DecoderTag.removeDecodeTag(text);
                        }
                        LOGGER4J.debug("replace text[" + text + "]");
                        break;
                    }
                }
            }
            fb.replace(offset, length, text, attr);
        } catch (Exception ex2) {
            LOGGER4J.error(ex2.getMessage(), ex2);
        }
    }

}
