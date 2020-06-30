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

import com.google.gson.GsonBuilder;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.zaproxy.zap.extension.automacrobuilder.GSONSaveObject.AppParmsIni_List;
import org.zaproxy.zap.extension.automacrobuilder.GSONSaveObject.AppValue_List;

/**
 * This class Used only when saving parameter settings.
 * 
 * @author daike
 */
public class ParmGenJSONSave {
    private static org.apache.logging.log4j.Logger logger4j =
            org.apache.logging.log4j.LogManager.getLogger();
    ParmGenMacroTrace pmt = null;
    private List<AppParmsIni> records;
    Iterator<AppParmsIni> it;
    ParmGenWriteFile pfile;
    public static final String JSONVERSION = "1.1"; // OUTPUT JSON VERSION
    public static ArrayList<PRequestResponse> selected_messages;
    public static ArrayList<PRequestResponse> proxy_messages;

    public ParmGenJSONSave(ParmGenMacroTrace _pmt, ArrayList<PRequestResponse> _selected_messages) {
        saveParmGenSetUp(_pmt, null);
        selected_messages = new ArrayList<PRequestResponse>();
        proxy_messages = _selected_messages;
        if(proxy_messages==null||proxy_messages.isEmpty()) {
            // create dummy message
            String requeststr = "GET /index.php?DB=1 HTTP/1.1\r\n"
                    + "Host: test\r\n"
                    + "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n\r\n"
                    ;
            String responsestr = "HTTP/1.1 200 OK\r\n"
                    + "Date: Sat, 20 Jun 2020 01:10:28 GMT\r\n"
                    + "Content-Length: 0\r\n"
                    + "Content-Type: text/html; charset=UTF-8\r\n\r\n";

            PRequestResponse dummy = new PRequestResponse("localhost" , 80, false, requeststr.getBytes(), responsestr.getBytes(), ParmVars.enc);
            proxy_messages = proxy_messages == null ? new ArrayList<>() : proxy_messages;
            proxy_messages.add(dummy);
        }
        selected_messages.add(proxy_messages.get(0));
        pfile = null;
    }

    public ParmGenJSONSave(List<AppParmsIni> _newparmcsv, ParmGenMacroTrace _pmt) {
        saveParmGenSetUp(_pmt, _newparmcsv);
        pfile = null;
    }

    private void saveParmGenSetUp(ParmGenMacroTrace _pmt, List<AppParmsIni> _newparmcsv) {
        pmt = _pmt;
        ParmGen pgen = new ParmGen(_pmt, _newparmcsv);
        records = ParmGen.parmcsv;
        logger4j.debug("records is " + (records == null ? "null" : "No null"));
        if (records == null) {
            records = new ArrayList<AppParmsIni>();
        }
        rewindAppParmsIni();
    }

    public void setParms(ArrayList<AppParmsIni> _records) {
        records = _records; // reference
    }

    public List<AppParmsIni> getrecords() {
        return records;
    }

    public void add(AppParmsIni pini) {

        records.add(pini);
    }

    public void mod(int i, AppParmsIni pini) {
        records.set(i, pini);
    }

    public void del(int i) {
        records.remove(i);
    }

    private String escapeDelimiters(String _d, String code) {
        // String _dd = _d.replaceAll("\\\\", "\\\\");
        String _dd = _d;
        // String _ddd = _dd.replaceAll("\"", "\"\"");
        String encoded = _d;
        try {
            if (code == null) {
                code = ParmVars.enc.getIANACharsetName();
            }
            if (_dd != null) {
                encoded = URLEncoder.encode(_dd, code);
            }
        } catch (UnsupportedEncodingException e) {
            ParmVars.plog.printException(e);
            encoded = _dd;
        }
        return encoded;
    }

    private String QUOTE(String val, boolean comma) {
        return "\"" + (val == null ? "" : val) + "\"" + (comma ? "," : "");
    }

    public void GSONsave() {
        // ファイル初期化
        ParmVars.plog.debuglog(0, "gsonsave called.");
        try {
            FileInfo finfo = new FileInfo(ParmVars.parmfile);
            pfile = new ParmGenWriteFile(finfo.getFullFileName());
        } catch (Exception ex) {
            ParmVars.plog.printException(ex);
            return;
        }

        pfile.truncate();

        GSONSaveObject gsobject = new GSONSaveObject();

        gsobject.VERSION = JSONVERSION;
        gsobject.LANG = ParmVars.enc.getIANACharsetName();
        gsobject.ProxyInScope = ParmGen.ProxyInScope;
        gsobject.IntruderInScope = ParmGen.IntruderInScope;
        gsobject.RepeaterInScope = ParmGen.RepeaterInScope;
        gsobject.ScannerInScope = ParmGen.ScannerInScope;

        // excludeMimeTypelist
        //
        // { "ExcludeMimeTypes" : ["image/.*", "application/json"],
        //

        ParmVars.ExcludeMimeTypes.forEach(
                (mtype) -> {
                    gsobject.ExcludeMimeTypes.add(mtype);
                });

        Iterator<AppParmsIni> it = records.iterator();
        while (it.hasNext()) {
            AppParmsIni prec = it.next();
            // String URL, String initval, String valtype, String incval, ArrayList<ParmGenParam>
            // parms
            AppParmsIni_List AppParmsIni_ListObj = new AppParmsIni_List();
            AppParmsIni_ListObj.URL = prec.getUrl();
            AppParmsIni_ListObj.len = prec.getLen();
            AppParmsIni_ListObj.typeval = prec.getTypeVal();
            AppParmsIni_ListObj.inival = prec.getIniVal();
            AppParmsIni_ListObj.maxval = prec.getMaxVal();
            AppParmsIni_ListObj.csvname =
                    (prec.getTypeVal() == AppParmsIni.T_CSV
                            ? escapeDelimiters(prec.getFrlFileName(), "UTF-8")
                            : "");
            AppParmsIni_ListObj.pause = prec.isPaused();
            AppParmsIni_ListObj.TrackFromStep = prec.getTrackFromStep();
            AppParmsIni_ListObj.SetToStep = prec.getSetToStep();
            AppParmsIni_ListObj.relativecntfilename = prec.getRelativeCntFileName();

            Iterator<AppValue> pt = prec.getAppValueReadWriteOriginal().iterator();

            while (pt.hasNext()) {
                AppValue param = pt.next();
                AppValue_List AppValue_ListObj = new AppValue_List();
                AppValue_ListObj.valpart = param.getValPart();
                AppValue_ListObj.isEnabled = param.isEnabled();
                AppValue_ListObj.isNoCount = param.isNoCount();
                AppValue_ListObj.csvpos = param.getCsvpos();
                AppValue_ListObj.value = escapeDelimiters(param.getVal(), null);
                AppValue_ListObj.resURL = param.getresURL() == null ? "" : param.getresURL();
                AppValue_ListObj.resRegex =
                        (escapeDelimiters(param.getresRegex(), null) == null
                                ? ""
                                : escapeDelimiters(param.getresRegex(), null));
                AppValue_ListObj.resValpart = param.getResValPart();
                AppValue_ListObj.resRegexPos = param.getResRegexPos();
                AppValue_ListObj.token = param.getToken() == null ? "" : param.getToken();
                AppValue_ListObj.urlencode = param.isUrlEncode();
                AppValue_ListObj.fromStepNo = param.getFromStepNo();
                AppValue_ListObj.toStepNo = param.getToStepNo();
                AppValue_ListObj.TokenType = param.getTokenType().name();

                AppParmsIni_ListObj.AppValue_List.add(AppValue_ListObj);
            }

            gsobject.AppParmsIni_List.add(AppParmsIni_ListObj);
        }

        // save Macros
        if (pmt != null) {
            pmt.GSONSave(gsobject);
        }

        PrintWriter pw = pfile.getPrintWriter();

        GsonBuilder gbuilder = new GsonBuilder();
        gbuilder.setPrettyPrinting();
        String prettygson = gbuilder.create().toJson(gsobject);
        pw.print(prettygson);

        // String jsonData = stWriter.toString();

        // pfile.print(jsonData);

        pfile.close();
        pfile = null;
        ParmVars.Saved();
    }

    public AppParmsIni getAppParmsIni(int i) {
        if (records.size() > i) {
            return records.get(i);
        }
        return null;
    }

    public void rewindAppParmsIni() {
        it = records.iterator();
    }

    public AppParmsIni getNextAppParmsIni() {
        if (it.hasNext()) {
            return it.next();
        }
        return null;
    }

    public int sizeAppParmsIni() {
        return records.size();
    }
}
