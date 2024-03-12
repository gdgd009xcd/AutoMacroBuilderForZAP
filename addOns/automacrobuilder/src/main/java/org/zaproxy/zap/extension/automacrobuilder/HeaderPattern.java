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

import java.util.Objects;
import java.util.regex.Pattern;

/** @author gdgd009xcd */
public class HeaderPattern {
    private String upperheadername;
    private String tkname_regexformat;
    private Pattern tkname_regpattern = null;
    private String tkname_regex = null;
    private String tkname = "";
    private int fcnt = 0;
    private String tkvalue_regexformat;
    private Pattern tkvalue_regpattern = null;
    private String tkvalue_regex = null;
    private String pathParam_RegexFormat = null;
    private ParmGenRequestTokenKey.RequestParamType rptype;
    private ParmGenRequestTokenKey.RequestParamSubType rpsubtype;
    private ParmGenToken foundResponseToken = null;

    HeaderPattern(
            String uhname,
            String name_regex,
            String value_regex,
            ParmGenRequestTokenKey.RequestParamType _rptype,
            ParmGenRequestTokenKey.RequestParamSubType _subtype) {
        upperheadername = uhname.toUpperCase();
        tkname_regexformat = name_regex;
        tkvalue_regexformat = value_regex;
        rptype = _rptype;
        rpsubtype = _subtype;
    }

    HeaderPattern(
            String uhname,
            String name_regex,
            String value_regex,
            String pathParam_regex,
            ParmGenRequestTokenKey.RequestParamType _rptype,
            ParmGenRequestTokenKey.RequestParamSubType _subtype) {
        upperheadername = uhname.toUpperCase();
        tkname_regexformat = name_regex;
        tkvalue_regexformat = value_regex;
        pathParam_RegexFormat = pathParam_regex;
        rptype = _rptype;
        rpsubtype = _subtype;
    }

    HeaderPattern(HeaderPattern src) {
        upperheadername = src.upperheadername;
        tkname_regexformat = src.tkname_regexformat;
        tkname_regpattern = src.tkname_regpattern;
        tkname_regex = src.tkname_regex;
        tkname = src.tkname;
        fcnt = src.fcnt;
        tkvalue_regexformat = src.tkvalue_regexformat;
        tkvalue_regpattern = src.tkvalue_regpattern;
        tkvalue_regex = src.tkvalue_regex;
        rptype = src.rptype;
        rpsubtype = src.rpsubtype;
        pathParam_RegexFormat = src.pathParam_RegexFormat;
        if (src.foundResponseToken != null) {
            foundResponseToken = new ParmGenToken(src.foundResponseToken);
        } else {
            foundResponseToken = null;
        }
    }

    public String getUpperHeaderName() {
        return upperheadername;
    }

    public Pattern getTokenName_RegexPattern(String tkvalue) {
        String escdtkvalue = ParmGenUtil.escapeRegexChars(tkvalue);
        tkname_regex = String.format(tkname_regexformat, escdtkvalue);
        tkname_regpattern =
                ParmGenUtil.Pattern_compile(
                        tkname_regex); // String.format("xxxx (name)=%s xxxx" , tkvalue)
        return tkname_regpattern;
    }

    public Pattern getTokenValue_RegexPattern(String _tkname) {
        String escdtkname = ParmGenUtil.escapeRegexChars(_tkname);
        tkvalue_regex = String.format(tkvalue_regexformat, escdtkname);
        tkvalue_regpattern =
                ParmGenUtil.Pattern_compile(
                        tkvalue_regex); // String.format("xxxx %s=(value) xxxx", tkname)
        return tkvalue_regpattern;
    }

    public String getTokenValueRegex() {
        return tkvalue_regex;
    }

    public String getTokenNameRegex() {
        return tkname_regex;
    }

    public ParmGenRequestTokenKey.RequestParamType getRequestParamType() {
        return rptype;
    }

    public ParmGenRequestTokenKey.RequestParamSubType getRequestParamSubType() {
        return rpsubtype;
    }

    public void setTkName(String _tkname) {
        tkname = _tkname;
    }

    public void setFcnt(int _fcnt) {
        fcnt = _fcnt;
    }

    public ParmGenRequestToken getQToken() {
        // ParmGenRequestToken(ParmGenRequestTokenKey.RequestParamType _rptype,
        // ParmGenRequestTokenKey.RequestParamSubType _subtype,String _name, String _value, int
        // _fcnt)
        return new ParmGenRequestToken(rptype, rpsubtype, tkname, "", fcnt);
    }

    public void setFoundResponseToken(ParmGenToken foundResponseToken) {
        this.foundResponseToken = foundResponseToken;
    }

    public ParmGenToken getFoundResponseToken() {
        return this.foundResponseToken;
    }

    // this hash doesn't care about fcnt. because request has same rptype/subtype/tkname tokens.
    public int getSameTokenHash() {
        return Objects.hash(rptype, rpsubtype, tkname);
    }

    public String generatePathParamter(int i) {
        StringBuilder pathParameterValue = new StringBuilder(tkname_regexformat);
        for (int j = 1; j < i; j++) {
            pathParameterValue.append(pathParam_RegexFormat);
        }
        pathParameterValue.append(tkvalue_regexformat);
        // update tkvalue_regex to pathParameterValue
        this.tkvalue_regex = pathParameterValue.toString();
        return this.tkvalue_regex;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof HeaderPattern)) return false;
        HeaderPattern that = (HeaderPattern) obj;
        return this.rptype == that.rptype
                && this.rpsubtype == that.rpsubtype
                && this.tkname.equals(that.tkname)
                && this.fcnt == that.fcnt;
    }

    @Override
    public int hashCode() {
        int hcode = Objects.hash(this.rptype, this.rpsubtype, this.tkname, this.fcnt);

        return hcode;
    }
}
