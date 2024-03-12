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

import org.zaproxy.zap.extension.automacrobuilder.generated.MacroBuilderUI;

import java.util.HashMap;

/** @author youtube */
public class ParmGenResTokenCollections {
    public HashMap<String, ParmGenToken> resTokenUrlDecodedNameSlashValueHash;
    public HashMap<String, ParmGenToken> resTokenUrlDecodedNameHash;
    public HashMap<String, ParmGenToken> resTokenUrlDecodedValueHash;
    public Encode resEncode;
    public int fromStepNo;

    /**
     * find Response token which has same requestToken's name and value
     *
     * @param requestToken
     * @return
     */
    public ParmGenToken findResponseToken(ParmGenToken requestToken) {
        String requestTokenName = null;
        ParmGenTokenKey requestParmGenTokenkey = requestToken.getTokenKey();
        if (requestParmGenTokenkey != null) {
            requestTokenName = requestParmGenTokenkey.getName();
        }

        ParmGenTokenValue requestParmGenTokenValue = requestToken.getTokenValue();
        String requestTokenValue = null;
        if (requestParmGenTokenValue != null) {
            requestTokenValue = requestParmGenTokenValue.getValue();
        }

        return findResponseToken(requestTokenName, requestTokenValue);
    }

    public ParmGenToken findResponseToken(ParmGenRequestToken requestToken) {
        String requestTokenName = null;
        ParmGenRequestTokenKey tokenKey = requestToken.getKey();
        if (tokenKey != null) {
            requestTokenName = tokenKey.getName();
        }

        String requestTokenValue = requestToken.getValue();

        return findResponseToken(requestTokenName, requestTokenValue);
    }

    /**
     * find Response token which has same name and value.
     *
     * @param name
     * @param value
     * @return
     */
    public ParmGenToken findResponseToken(String name, String value) {
        if (name == null || value == null) return null;

        String requestTokenNameDecoded =
                ParmGenUtil.URLdecode(name, resEncode.getIANACharsetName());
        String requestTokenValueDecoded =
                ParmGenUtil.URLdecode(value, resEncode.getIANACharsetName());
        String nameSlashValue = requestTokenNameDecoded + "/" + requestTokenValueDecoded;
        ParmGenToken foundNameAndValueResToken =
                resTokenUrlDecodedNameSlashValueHash.get(nameSlashValue);
        ParmGenToken foundNameResToken = resTokenUrlDecodedNameHash.get(requestTokenNameDecoded);
        ParmGenToken foundValueResToken = resTokenUrlDecodedValueHash.get(requestTokenValueDecoded);
        ParmGenToken foundResToken = null;

        if (foundNameAndValueResToken
                != null) { // exactly request parameter matched response parameter's name & value
            foundResToken = foundNameAndValueResToken;
        } else if (foundValueResToken != null && foundValueResToken.isEnabled()) { //
            foundResToken = foundValueResToken;
        } else if (foundNameResToken != null && foundNameResToken.isEnabled()) {
            String foundNameResTokenValueDecoded =
                    ParmGenUtil.URLdecode(
                            foundNameResToken.getTokenValue().getValue(),
                            resEncode.getIANACharsetName());
            if (foundNameResTokenValueDecoded != null
                    && foundNameResTokenValueDecoded.length()
                            == requestTokenValueDecoded.length()) {
                foundResToken = foundNameResToken;
            } else if(foundNameResToken.getTokenKey().getName().toLowerCase().equals(MacroBuilderUI.RAILS_CSRF_TOKEN)) {
                foundResToken = foundNameResToken;
            }
        }

        return foundResToken;
    }
}
