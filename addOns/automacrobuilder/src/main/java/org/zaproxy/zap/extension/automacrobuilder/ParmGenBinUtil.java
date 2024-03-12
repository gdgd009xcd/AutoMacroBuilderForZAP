package org.zaproxy.zap.extension.automacrobuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/** @author gdgd009xcd */
//
// ByteArray
//
public class ParmGenBinUtil {

    private ByteArrayOutputStream bstream = null;

    public ParmGenBinUtil() {
        bstream = new ByteArrayOutputStream();
    }

    public ParmGenBinUtil(byte[] bin) {
        initParmGenBinUtil(bin);
    }

    public void initParmGenBinUtil(byte[] bin) {
        bstream = new ByteArrayOutputStream();
        concat(bin);
    }

    public int length() {
        return bstream.size();
    }

    /**
     * add byte array to bstream
     *
     * @param bin
     * @return
     */
    public boolean concat(byte[] bin) {

        if ((bin == null)) {
            return false;
        }

        try {
            bstream.write(bin);
        } catch (IOException e) {

            return false;
        }
        return true;
    }

    public byte[] getBytes() {
        if (bstream == null) {
            return null;
        }
        return bstream.toByteArray();
    }

    /**
     * get byte array between beginIndex and endIndex within bstream
     * org[beginIndex] - org[endIndex-1] length = endIndex - beginIndex > 0
     *
     * @param beginIndex
     * @param endIndex
     * @return
     */
    public byte[] subBytes(int beginIndex, int endIndex) {

        int length = endIndex - beginIndex; // 戻り値配列の要素数
        if (length > 0 && beginIndex >= 0 && length() >= endIndex) {
            byte[] org = getBytes();
            byte[] result = new byte[length];
            System.arraycopy(org, beginIndex, result, 0, length);
            return result;
        }

        return null;
    }


    /**
     * get byte array from beginIndex until last.
     *
     * @param beginIndex
     * @return
     */
    public byte[] subBytes(int beginIndex) {
        return subBytes(beginIndex, length());
    }

    /** indexOf */
    @Deprecated
    public int indexOfobsolete(byte[] dest, int startpos) {
        int idx = -1;
        byte[] seqbin = getBytes();
        byte[] keybin = dest;

        int endpos = seqbin.length - keybin.length + 1;

        if (endpos > 0 && startpos < endpos) {
            for (int i = startpos; i < endpos; i++) {
                for (int j = 0; j < keybin.length; j++) {
                    // System.out.println("  i,j="  + i + "," + j);

                    if (seqbin[i + j] == keybin[j]) {
                        if (j == keybin.length - 1) {
                            idx = i;
                            // System.out.println(" result idx,i,j=" + idx+ "," + i + "," + j);
                            break;
                        }

                    } else {
                        break;
                    }
                }
                if (idx != -1) break;
            }
        }

        return idx;
    }

    /**
     *  get index of first occurrence of dest sequence ｗithin this byte sequence
     *
     * @param dest
     * @param startpos
     * @return
     */
    public int indexOf(byte[] dest, int startpos) {
        byte[] seqbin = getBytes();
        byte[] keybin = dest;

        if (seqbin == null ||  keybin == null) return -1;

        int seqLen = seqbin.length;
        int keyLen = keybin.length;
        int endpos = seqLen - keyLen + 1;

        if (seqLen < 1 || keyLen < 1) return -1;

        if (endpos > 0 && startpos < endpos) {
            byte c = keybin[0];
            int i = startpos;

            if (keyLen == 1) {
                return nextFirstBytePos(i, seqbin, c, keyLen);
            } else {
                while ((i = nextFirstBytePos(i, seqbin, c, keyLen)) != -1) {
                    int j;
                    for (j = 1; j < keyLen; j++) {
                        if (seqbin[i + j] != keybin[j]) {
                            break;
                        }
                    }
                    if (j == keyLen) {
                        return i;
                    }
                    i++;
                }
            }
        }
        return -1;
    }

    /** */
    public int indexOf(byte[] dest) {
        return indexOf(dest, 0);
    }

    public int indexOf(byte dest) {
        byte[] b = {dest};
        return indexOf(b, 0);
    }

    /** clear data */
    public void clear() {
        bstream.reset();
    }

    private int nextFirstBytePos(int start, byte[] src, byte c, int destLen) {
        int srcLen = src.length;
        int minLen = srcLen - destLen;
        for(int i=start; i < srcLen; i++) {
            if(src[i] == c ){
                if(i <= minLen){
                    return i;
                } else {
                    break;
                }
            }
        }
        return -1;
    }
}
