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
package org.zaproxy.zap.extension.automacrobuilder;

import java.util.ArrayList;
import java.util.Collection;

/**
 * GSON output class for save configration to file
 *
 * @author gdgd009xcd
 */
public class GSONSaveObjectV2 {
    public String VERSION = "2.00"; // configuration file version;
    public boolean ProxyInScope;
    public boolean IntruderInScope;
    public boolean RepeaterInScope;
    public boolean ScannerInScope;
    public Collection<String> ExcludeMimeTypes;
    public Collection<AppParmAndSequence> AppParmAndSequences;

    GSONSaveObjectV2() {
        ExcludeMimeTypes = new ArrayList<>();
        AppParmAndSequences = new ArrayList<>();
    }

    static class AppParmAndSequence {
        public int MyPageIndex; // position index of MyPage in PRequestResponse list
        public int CurrentRequest; // position index of current selected request in PRequestResponse
        public String sequenceCharsetName; // CharSetName of entire PRequestResponses sequence
        // list
        public Collection<GsonPRequestResponse> PRequestResponses; // RequestResponse sequence list
        public Collection<AppParmsIni_List> AppParmsIni_Lists;

        public AppParmAndSequence() {
            sequenceCharsetName = Encode.UTF_8.getIANACharsetName();
            AppParmsIni_Lists = new ArrayList<>();
            PRequestResponses = new ArrayList<>();
        }
    }

    // innner static classes
    static class AppParmsIni_List {
        public String URL;
        public int len;
        public int typeval;
        public int inival;
        public int maxval;
        public String csvname;
        public boolean pause;
        public int TrackFromStep;
        public int SetToStep;
        public String relativecntfilename;
        public Collection<AppValue_List> AppValue_Lists;

        AppParmsIni_List() {
            AppValue_Lists = new ArrayList<>();
        }
    }

    static class AppValue_List {
        public String valpart;
        public boolean isEnabled;
        public boolean isNoCount;
        public int csvpos;
        public String value;
        public String resURL;
        public String resRegex;
        public String resValpart;
        public int resRegexPos;
        public String token;
        public boolean urlencode;
        public int fromStepNo;
        public int toStepNo;
        public String TokenType;
        public int condTargetNo;
        public String condRegex;
        public boolean condRegexTargetIsRequest;
        public boolean replaceZeroSize;
    }

    static class GsonPRequestResponse {
        public String PRequest64;
        public String PResponse64;
        public String Host;
        public int Port;
        public boolean SSL;
        public String Comments;
        public boolean Disabled;
        public boolean Error;
        public String RequestCharsetName;
        public String ResponseCharsetName;

        GsonPRequestResponse() {
            init();
        }

        public void init() {
            PRequest64 = null;
            PResponse64 = null;
            Host = null;
            Port = 0;
            SSL = false;
            Comments = "";
            Disabled = false;
            Error = false;
            RequestCharsetName = null;
            ResponseCharsetName = null;
        }
    }
}
