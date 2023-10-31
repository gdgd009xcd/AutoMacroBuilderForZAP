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

import static org.zaproxy.zap.extension.automacrobuilder.Encode.UTF_8;
import static org.zaproxy.zap.extension.automacrobuilder.EnvironmentVariables.JSONFileIANACharsetName;

import com.google.gson.GsonBuilder;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;

/**
 * This class Used only when saving parameter settings.
 *
 * @author gdgd009xcd
 */
public class ParmGenGSONSaveV2 {
    private static org.apache.logging.log4j.Logger logger4j =
            org.apache.logging.log4j.LogManager.getLogger();
    ParmGenWriteFile pfile;
    private ParmGenMacroTraceProvider pmtProvider = null;
    public static ArrayList<PRequestResponse> selected_messages = null;
    public static ArrayList<PRequestResponse> proxy_messages = null;

    /**
     * Constructor for customActionPerformed method
     *
     * @param _selected_messages
     */
    public ParmGenGSONSaveV2(
            ParmGenMacroTraceProvider pmtProvider, ArrayList<PRequestResponse> _selected_messages) {
        this.pmtProvider = pmtProvider;
        selected_messages = new ArrayList<PRequestResponse>();
        proxy_messages = _selected_messages;
        if (proxy_messages == null || proxy_messages.isEmpty()) {
            // create dummy message
            String requeststr =
                    "GET /index.php?DB=1 HTTP/1.1\r\n"
                            + "Host: test\r\n"
                            + "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n\r\n";
            String responsestr =
                    "HTTP/1.1 200 OK\r\n"
                            + "Date: Sat, 20 Jun 2020 01:10:28 GMT\r\n"
                            + "Content-Length: 0\r\n"
                            + "Content-Type: text/html; charset=UTF-8\r\n\r\n";

            PRequestResponse dummy =
                    new PRequestResponse(
                            "localhost",
                            80,
                            false,
                            requeststr.getBytes(),
                            responsestr.getBytes(),
                            UTF_8,
                            UTF_8);
            proxy_messages = proxy_messages == null ? new ArrayList<>() : proxy_messages;
            proxy_messages.add(dummy);
        }
        selected_messages.add(proxy_messages.get(0));
        pfile = null;
    }

    public ParmGenGSONSaveV2(ParmGenMacroTraceProvider pmtProvider) {
        this.pmtProvider = pmtProvider;
        pfile = null;
    }

    /**
     * convert String to URLencode (code is UTF-8)
     *
     * @param _d
     * @return URLencoded with UTF-8
     */
    private String URLencodeToJSON(String _d) {
        // String _dd = _d.replaceAll("\\\\", "\\\\");
        String _dd = _d;
        // String _ddd = _dd.replaceAll("\"", "\"\"");
        String encoded = _d;
        try {
            if (_dd != null) {
                encoded = URLEncoder.encode(_dd, JSONFileIANACharsetName);
            }
        } catch (UnsupportedEncodingException e) {
            EnvironmentVariables.plog.printException(e);
            encoded = _dd;
        }
        return encoded;
    }

    private String QUOTE(String val, boolean comma) {
        return "\"" + (val == null ? "" : val) + "\"" + (comma ? "," : "");
    }

    public void GSONsave() {
        // ファイル初期化
        try {
            FileInfo finfo = new FileInfo(EnvironmentVariables.parmfile);
            pfile = new ParmGenWriteFile(finfo.getFullFileName());
        } catch (Exception ex) {
            EnvironmentVariables.plog.printException(ex);
            return;
        }

        pfile.truncate();

        GSONSaveObjectV2 gsobject = new GSONSaveObjectV2();

        gsobject.ProxyInScope = ParmGen.ProxyInScope;
        gsobject.IntruderInScope = ParmGen.IntruderInScope;
        gsobject.RepeaterInScope = ParmGen.RepeaterInScope;
        gsobject.ScannerInScope = ParmGen.ScannerInScope;

        // excludeMimeTypelist
        //
        // { "ExcludeMimeTypes" : ["image/.*", "application/json"],
        //

        EnvironmentVariables.ExcludeMimeTypes.forEach(
                (mtype) -> {
                    gsobject.ExcludeMimeTypes.add(mtype);
                });

        Iterator<ParmGenMacroTrace> pit = pmtProvider.getBaseInstanceIterator();
        while (pit.hasNext()) {
            ParmGenMacroTrace pmt = pit.next();
            if (pmt.getAppParmsIniList() == null) {
                pmt.updateAppParmsIniAndClearCache(null);
            }
            Iterator<AppParmsIni> it = pmt.getIteratorOfAppParmsIni();
            GSONSaveObjectV2.AppParmAndSequence appParmAndSequence =
                    new GSONSaveObjectV2.AppParmAndSequence();
            while (it.hasNext()) {
                AppParmsIni prec = it.next();
                // String URL, String initval, String valtype, String incval,
                // ArrayList<ParmGenParam>
                // parms
                GSONSaveObjectV2.AppParmsIni_List AppParmsIni_ListObj =
                        new GSONSaveObjectV2.AppParmsIni_List();
                AppParmsIni_ListObj.URL = prec.getUrl();
                AppParmsIni_ListObj.len = prec.getLen();
                AppParmsIni_ListObj.typeval = prec.getTypeVal();
                AppParmsIni_ListObj.inival = prec.getIniVal();
                AppParmsIni_ListObj.maxval = prec.getMaxVal();
                AppParmsIni_ListObj.csvname =
                        (prec.getTypeVal() == AppParmsIni.T_CSV
                                ? URLencodeToJSON(prec.getFrlFileName())
                                : "");
                AppParmsIni_ListObj.pause = prec.isPaused();
                AppParmsIni_ListObj.TrackFromStep = prec.getTrackFromStep();
                AppParmsIni_ListObj.SetToStep = prec.getSetToStep();
                AppParmsIni_ListObj.relativecntfilename = prec.getRelativeCntFileName();

                Iterator<AppValue> pt = prec.getAppValueReadWriteOriginal().iterator();

                while (pt.hasNext()) {
                    AppValue param = pt.next();
                    GSONSaveObjectV2.AppValue_List AppValue_ListObj =
                            new GSONSaveObjectV2.AppValue_List();
                    AppValue_ListObj.valpart = param.getValPart();
                    AppValue_ListObj.isEnabled = param.isEnabled();
                    AppValue_ListObj.isNoCount = param.isNoCount();
                    AppValue_ListObj.csvpos = param.getCsvpos();
                    AppValue_ListObj.value = URLencodeToJSON(param.getVal());
                    AppValue_ListObj.resURL = param.getresURL() == null ? "" : param.getresURL();
                    AppValue_ListObj.resRegex =
                            (URLencodeToJSON(param.getresRegex()) == null
                                    ? ""
                                    : URLencodeToJSON(param.getresRegex()));
                    AppValue_ListObj.resValpart = param.getResValPart();
                    AppValue_ListObj.resRegexPos = param.getResRegexPos();
                    AppValue_ListObj.token = param.getToken() == null ? "" : param.getToken();
                    AppValue_ListObj.urlencode = param.isUrlEncode();
                    AppValue_ListObj.fromStepNo = param.getFromStepNo();
                    AppValue_ListObj.toStepNo = param.getToStepNo();
                    AppValue_ListObj.TokenType = param.getTokenType().name();
                    AppValue_ListObj.condTargetNo = param.getCondTargetNo();
                    AppValue_ListObj.condRegex =
                            (URLencodeToJSON(param.getCondRegex()) == null
                                    ? ""
                                    : URLencodeToJSON(param.getCondRegex()));
                    AppValue_ListObj.condRegexTargetIsRequest = param.requestIsCondRegexTarget();

                    AppParmsIni_ListObj.AppValue_Lists.add(AppValue_ListObj);
                }

                appParmAndSequence.AppParmsIni_Lists.add(AppParmsIni_ListObj);
            }

            // save RequestResponses
            pmt.GSONSaveV2(appParmAndSequence);
            gsobject.AppParmAndSequences.add(appParmAndSequence);
        }

        PrintWriter pw = pfile.getPrintWriter();

        GsonBuilder gbuilder = new GsonBuilder();
        gbuilder.setPrettyPrinting();
        String prettygson = gbuilder.create().toJson(gsobject);
        pw.print(prettygson);

        pfile.close();
        pfile = null;
        EnvironmentVariables.Saved(true);
    }
}
