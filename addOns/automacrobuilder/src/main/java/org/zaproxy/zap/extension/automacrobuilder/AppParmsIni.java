/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.automacrobuilder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.*;
import java.util.regex.Pattern;

/** @author gdgd009xcd */
//
// class AppParmsIni
//
public class AppParmsIni {
    private static org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();

    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");
    private String url;
    private Pattern urlregex;
    private ArrayList<AppValue> parmlist = null;
    private Iterator<AppValue> it;
    private int len = 4;
    private String type;
    private int typeval; // number:0, rand:1, csv:2, track:3
    private int inival = 0;
    private int maxval = 2147483646;
    private FileReadLine frl = null;
    private String csvname = null;
    private String exerr = "";
    private String relativecntfile = ""; // filename only. no contain directory.
    private String cstrcnt = null;
    private int rndval = 1;
    // public int row;
    private Boolean pause = false;
    private int TrackFromStep = -1; // StepNo== -1:any  >0:TrackingFrom
    private int SetToStep =
            ParmVars.TOSTEPANY; // == TOSTEPANY:any   0<= SetToStep < TOSTEPANY:SetTo

    public static final int T_NUMBER = 0; // 数値昇順
    public static final int T_RANDOM = 1; // 乱数
    public static final int T_CSV = 2; // CSV入力
    public static final int T_TRACK = 3; // レスポンス追跡
    public static final int T_TAMPER = 4; // TamperProxy
    public static final String T_NUMBER_NAME = "number";
    public static final String T_RANDOM_NAME = "random";
    public static final String T_CSV_NAME = "csv";
    public static final String T_TRACK_NAME = "track";
    public static final String T_TAMPER_NAME = "tamper";
    public static final int T_NUMBER_AVCNT = 2;
    public static final int T_RANDOM_AVCNT = 2;
    public static final int T_CSV_AVCNT = 2;
    public static final int T_TRACK_AVCNT = 8; // csvファイルの旧フォーマットinival==0時は読み込み時のみ6
    public static final int T_TRACK_OLD_AVCNT = 6;
    public static final int T_TAMPER_AVCNT = 8;

    public void setCsvName(String csvname) {
        this.csvname = csvname;
    }

    public String getCsvName() {
        return this.csvname;
    }

    public void crtFrl(String filepath, boolean savekeep) {
        frl = new FileReadLine(filepath, savekeep);
    }

    public String getFrlFileName() {
        if (frl != null) {
            return frl.getFileName();
        }
        return null;
    }

    public void setLen(int len) {
        this.len = len;
    }

    public int getLen() {
        return this.len;
    }

    public enum NumberCounterTypes {
        NumberCount,
        DateCount,
    }

    public void setTrackFromStep(int _step) {
        TrackFromStep = _step;
    }

    public int getTrackFromStep() {
        return TrackFromStep;
    }

    public void setSetToStep(int _step) {
        SetToStep = _step;
    }

    public int getSetToStep() {
        return SetToStep;
    }

    /**
     * is Paused
     *
     * <p>Get boolean pause value
     */
    public boolean isPaused() {
        return pause;
    }

    /**
     * Set pause when JSON load/parameter generate
     *
     * @param b boolean
     */
    public void initPause(boolean b) {
        this.pause = b;
    }

    /**
     * Update pause status when GUI manipulation
     *
     * @param b boolean
     */
    public void updatePause(boolean b) {
        pause = b;
        String _c = getCurrentValue();
        switch (typeval) {
            case T_NUMBER:
            case T_CSV:
                int _i = Integer.parseInt(_c);
                if (pause) {
                    if (_i > 0) {
                        _i--; // >0 ならデクリメントして元に戻す
                        updateCurrentValue(_i);
                    }
                } else {
                    _i++; // インクリメント
                    updateCurrentValue(_i);
                }
                break;
            case T_TRACK:
                break;
            case T_RANDOM:
                break;
        }
    }

    /*int getRow(){
    	return row;
    }*/

    public void clearAppValues() {
        /*
        if (parmlist != null) {
            for (AppValue ap : parmlist) {
                ParmGenTrackKeyPerThread.remove(ap.getTrackKey());// これは不要。なぜなら、GSONSave時にFetchResponseValはNULLされる。
            }
        }
        */
        parmlist = new ArrayList<AppValue>();
    }

    public void addAppValue(AppValue app) {
        if (parmlist != null) {
            // app.setCol(parmlist.size());
            parmlist.add(app);
        }
    }

    public int getIniVal() {
        return this.inival;
    }

    public void setIniVal(int inival) {
        this.inival = inival;
    }

    public int getMaxVal() {
        return this.maxval;
    }

    public void setMaxVal(int maxval) {
        this.maxval = maxval;
    }

    public String getIniValDsp() {
        switch (typeval) {
            case T_NUMBER:
                return Integer.toString(inival);
            case T_CSV:
                return frl.getFileName();
            case T_TRACK:
                return "";
            case T_RANDOM:
                return "";
        }
        return "";
    }

    public String getTypeValDspString() {
        switch (typeval) {
            case T_NUMBER:
                return bundle.getString("ParmGen.数値昇順.text");
            case T_CSV:
                return bundle.getString("ParmGen.CSVファイル昇順.text");
            case T_RANDOM:
                return bundle.getString("ParmGen.乱数.text");
            case T_TRACK:
                return bundle.getString("ParmGen.追跡.text");
            case T_TAMPER:
                return bundle.getString("ParmGen.TAMPERPROXY.text");
        }
        return "";
    }

    public void setTypeValFromString(String _type) {
        type = _type;
        if (type.indexOf(T_RANDOM_NAME) != -1) { // random
            for (int x = 0; x < len; x++) {
                rndval = rndval * 10;
            }
            typeval = T_RANDOM;
        } else if (type.indexOf(T_NUMBER_NAME) != -1) {
            typeval = T_NUMBER;
        } else if (type.indexOf(T_TRACK_NAME) != -1) {
            typeval = T_TRACK;
        } else if (type.indexOf(T_TAMPER_NAME) != -1) {
            typeval = T_TAMPER;
        } else {
            typeval = T_CSV;
        }
    }

    public int getTypeVal() {
        return typeval;
    }

    public void setTypeVal(int typeval) {
        this.typeval = typeval;
    }

    public int getReadAVCnt(int _plen) {
        switch (typeval) {
            case T_NUMBER:
                return T_NUMBER_AVCNT;
            case T_CSV:
                return T_CSV_AVCNT;
            case T_RANDOM:
                return T_RANDOM_AVCNT;
            case T_TAMPER:
                return T_TAMPER_AVCNT;
            case T_TRACK:
                if (_plen > 0) return _plen; // parameter count
                else {
                    return T_TRACK_OLD_AVCNT; // 旧フォーマット
                }
        }
        return 0;
    }

    public String getLenDsp() {
        return Integer.toString(len);
    }

    public int getAppValuesLineCnt() {
        if (parmlist != null) {
            int l = parmlist.size();
            if (l <= 0) l = 1;
            return l;
        }
        return 1;
    }

    public String getAppValuesDsp() {
        it = parmlist.iterator();
        String appvalues = "";
        while (it.hasNext()) {
            AppValue ap = it.next();
            if (appvalues.length() > 0) {
                appvalues += "\n";
            }
            appvalues += ap.getAppValueDsp(typeval);
        }
        return appvalues;
    }

    public String setUrl(String _url) {
        exerr = null;
        try {
            url = _url;
            urlregex = ParmGenUtil.Pattern_compile(url);

        } catch (Exception e) {
            urlregex = null;
            exerr = e.toString();
        }
        return exerr;
    }

    public String getUrl() {
        return url;
    }

    public Pattern getPatternUrl() {
        return urlregex;
    }

    // --------------constructors begin----------------

    public AppParmsIni() {
        setCntFileNameNew();
        parmlist = new ArrayList<AppValue>();
        rewindAppValues();
    }
    // --------------constructors end----------------

    public String getTypeValToString() {
        switch (typeval) {
            case T_NUMBER:
                return T_NUMBER_NAME;
            case T_RANDOM:
                return T_RANDOM_NAME;
            case T_CSV:
                return T_CSV_NAME;
            case T_TRACK:
                return T_TRACK_NAME;
            case T_TAMPER:
                return T_TAMPER_NAME;
            default:
                break;
        }
        return "";
    }

    private String getCurrentSaveDir() {
        File cfile = new File(ParmVars.parmfile);
        String dirname = cfile.getParent();
        return dirname;
    }

    private String crtRandomFileName() {
        String fname = null;

        UUID uuid = UUIDGenerator.getUUID();
        String uustr = uuid.toString();
        fname = uustr + ".txt";
        return fname;
    }

    private String getCntFullPathName() {
        String fname = null;
        File cfile = new File(ParmVars.parmfile);
        String dirname = getCurrentSaveDir();
        String filename = cfile.getName();

        int lastpos = filename.lastIndexOf(".");
        int slen = filename.length();
        String name = filename;
        if (lastpos > 0 && slen > lastpos) {
            String prefix = filename.substring(0, lastpos);
            String suffix = filename.substring(lastpos + 1);
            name = prefix;
        }

        fname = dirname + ParmVars.fileSep + name + "_" + relativecntfile;
        return fname;
    }

    private void setCntFileNameNew() {
        if (relativecntfile == null || relativecntfile.length() == 0) {
            relativecntfile = crtRandomFileName();
        }
    }

    public void setRelativeCntFileName(String f) {
        relativecntfile = f;
    }

    public String getRelativeCntFileName() {
        return relativecntfile;
    }

    /*
    void setRowAndCntFile(int _r){//deprecated. 2021/1 will be deleted.
        row = _r;
        setCntFileName();
    }*/

    /*void setRow(int r){
        row = r;
    }*/

    // when entry AppParmIni/AppValue modified, accidentally last AppValue entry NOCOUNT flag maybe
    // be set.
    // so it must be clear NOCOUNT.
    public void clearLastAppValueNOCOUNT() {

        if (parmlist != null) {
            int plast = parmlist.size() - 1;
            if (plast >= 0) {
                AppValue av = parmlist.get(plast);
                av.clearNoCount();
                parmlist.set(plast, av);
            }
        }
    }

    String getFillZeroInt(int v) {
        String nval = Integer.toString(v);
        int zero = len - nval.length();
        while (zero > 0) {
            nval = "0" + nval;
            zero--;
        }
        return nval;
    }

    String getGenValue(
            ParmGenMacroTrace pmt,
            AppValue apv,
            ParmGenTokenKey tk,
            int currentStepNo,
            int toStepNo,
            int _valparttype,
            int csvpos) {
        int n;
        switch (typeval) {
            case T_NUMBER: // number
                n = countUp(_valparttype, this, apv, pmt); // synchronized
                if (n > -1) {
                    return getFillZeroInt(n); // thread safe
                } else {
                    return null;
                }
            case T_RANDOM: // random
                Random rand = new Random();
                n = rand.nextInt(rndval);
                return getFillZeroInt(n); // thread safe
            case T_TRACK: // loc
                // if ( global.Location != void ){
                return pmt.getFetchResponseVal()
                        .getLocVal(
                                apv.getTrackKey(),
                                tk,
                                currentStepNo,
                                toStepNo,
                                apv); // per thread object
                // }
            default: // csv
                if (frl != null) {
                    LOGGER4J.debug("frl.csvfile:" + frl.csvfile);
                    if (csvpos == -1) {
                        csvpos = len;
                    }
                    return frl.readLine(
                            _valparttype,
                            csvpos,
                            this,
                            apv,
                            pmt); // read CSV 1 record. synchronized
                } else {
                    LOGGER4J.debug("getGenValue frl is NULL");
                }
                break;
        }
        return null;
    }

    String getStrCnt(
            ParmGenMacroTrace pmt,
            AppValue apv,
            ParmGenTokenKey tk,
            int currentStepNo,
            int toStepNo,
            int _valparttype,
            int csvpos) {
        // if ( cstrcnt == null|| typeval == 3){
        cstrcnt = getGenValue(pmt, apv, tk, currentStepNo, toStepNo, _valparttype, csvpos);
        // }
        return cstrcnt;
    }

    synchronized int countUp(
            int _valparttype, AppParmsIni _parent, AppValue apv, ParmGenMacroTrace pmt) {
        // counter file open
        int cnt = inival;
        try {

            FileReader fr = new FileReader(getCntFullPathName());
            BufferedReader br = new BufferedReader(fr);
            String rdata;
            String alldata = "";
            while ((rdata = br.readLine()) != null) {
                rdata = rdata.replace("\r", "");
                rdata = rdata.replace("\n", "");
                alldata += rdata;
            }
            cnt = Integer.valueOf(alldata).intValue();

            fr.close();

        } catch (Exception e) {
            LOGGER4J.error("read file:" + getCntFullPathName() + " " + e.toString(), e);
            cnt = inival;
        }

        int ncnt = cnt + 1;

        boolean condInValid = false;
        if (pmt != null && apv != null) {
            condInValid = !pmt.getFetchResponseVal().getCondValid(apv) && apv.hasCond();
        }
        if (condInValid
                || ((_valparttype & AppValue.C_NOCOUNT) == AppValue.C_NOCOUNT)
                || _parent.isPaused()) {
            ncnt = cnt; // no countup
        } else if (ncnt > maxval) {
            LOGGER4J.debug(
                    "CountUp maxval reached. reset to inival"
                            + Integer.toString(ncnt)
                            + "->"
                            + Integer.toString(inival));
            ncnt = inival;
        } else {
            LOGGER4J.debug("CountUp ncnt:" + Integer.toString(ncnt));
        }

        if ((_valparttype & AppValue.C_NOCOUNT) != AppValue.C_NOCOUNT) {
            try {
                FileWriter filewriter = new FileWriter(getCntFullPathName(), false);
                String s1 = String.valueOf(ncnt);
                filewriter.write(s1);
                filewriter.close();
            } catch (Exception e) {
                LOGGER4J.error("write file:" + getCntFullPathName() + " " + e.toString(), e);
                throw new RuntimeException(e.toString());
            }
        }
        return cnt;
    }

    int updateCounter(int i) {
        if (i >= 0) {
            try {
                LOGGER4J.debug("cntfile:" + getCntFullPathName());
                FileWriter filewriter = new FileWriter(getCntFullPathName(), false);
                String s1 = String.valueOf(i);
                filewriter.write(s1);
                filewriter.close();
            } catch (Exception e) {
                LOGGER4J.error("updateCounter", e);
                return -1;
            }
        }
        return i;
    }

    /*int updateCSV(int i) {
        return frl.skipLine(i);
    }*/

    public String getCurrentValue() {
        String rval = null;
        switch (typeval) {
            case T_NUMBER:
                int i = countUp(AppValue.C_NOCOUNT, this, null, null); // synchronized
                rval = Integer.toString(i);
                break;
            case T_RANDOM:
                break;
            case T_CSV:
                rval = frl.getCurrentReadLine(AppValue.C_NOCOUNT, 0, this); // synchronized
                // rval = String.valueOf(frl.current_line);
                break;
            case T_TRACK:
                break;
            default:
                break;
        }
        return rval;
    }

    public String updateCurrentValue(int i) {
        int r = -1;
        String rval = null;
        switch (typeval) {
            case T_NUMBER:
                r = updateCounter(i);
                if (r != -1) {
                    rval = Integer.toString(r);
                }
                break;
            case T_RANDOM:
                break;
            case T_CSV:
                r = frl.skipLine(i);
                if (r != -1) {
                    rval = String.valueOf(r);
                }
                break;
            case T_TRACK:
                break;
            default:
                break;
        }
        return rval;
    }

    public final void rewindAppValues() {
        if (parmlist != null) {
            it = parmlist.iterator();
        } else {
            it = null;
        }
    }

    /**
     * get JTable row which is generated from AppValue
     *
     * @return Object[]
     */
    public Object[] getNextAppValuesRow() {
        AppValue app;
        if (it != null && it.hasNext()) {
            app = it.next();
            switch (typeval) {
                case T_NUMBER:
                    return new Object[] {
                        app.getValPart(),
                        (app.isEnabled() ? false : true),
                        app.getVal(),
                        app.isNoCount() ? false : true
                    };
                case T_RANDOM:
                    break;
                case T_CSV:
                    return new Object[] {
                        app.getValPart(),
                        (app.isEnabled() ? false : true),
                        app.getCsvpos(),
                        app.getVal(),
                        app.isNoCount() ? false : true
                    };
                case T_TRACK:
                    return new Object[] {
                        app.getValPart(),
                        (app.isEnabled() ? false : true),
                        app.getVal(),
                        app.getresURL(),
                        app.getresRegex(),
                        app.getResValPart(),
                        Integer.toString(app.getResRegexPos()),
                        app.getToken(),
                        app.isUrlEncode(),
                        app.getFromStepNo() == -1 ? "*" : Integer.toString(app.getFromStepNo()),
                        app.getToStepNo() == ParmVars.TOSTEPANY
                                ? "*"
                                : Integer.toString(app.getToStepNo()),
                        app.getTokenType().name(),
                        app.getCondRegex(),
                        app.getCondTargetNo(),
                        app.requestIsCondRegexTarget(),
                        app.isReplaceZeroSize()
                    };
                default:
                    break;
            }
        }
        return null;
    }

    /**
     * whether this object is same as argument specified or not.
     *
     * @param bini
     * @return
     */
    public boolean isSameContents(AppParmsIni bini) {

        if (ParmGenUtil.nullableStringEquals(this.url, bini.url)
                && this.len == bini.len
                && ParmGenUtil.nullableStringEquals(this.type, bini.type)
                && this.typeval == bini.typeval
                && this.inival == bini.inival
                && this.maxval == bini.maxval
                && ParmGenUtil.nullableStringEquals(this.getFrlFileName(), bini.getFrlFileName())
                && this.TrackFromStep == bini.TrackFromStep
                && this.SetToStep == bini.SetToStep) {
            boolean issame = true;
            for (AppValue thisapp : this.parmlist) {
                for (AppValue otherapp : bini.parmlist) {
                    if (!thisapp.isSameContents(otherapp)) {
                        issame = false;
                        break;
                    }
                }
            }
            return issame;
        }
        return false;
    }

    /**
     * Get modifiable {@code List<AppValue>} Original.
     *
     * @return parmlist {@code List<AppValue>}
     */
    public List<AppValue> getAppValueReadWriteOriginal() {
        return parmlist;
    }
}
