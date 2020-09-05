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

/** @author gdgd009xcd */
class PathComparator<T extends CookiePathValue> implements java.util.Comparator<T> {
    @Override
    public int compare(T s, T t) {
        String spath = s.getPath();
        String tpath = t.getPath();
        //
        // s > t  : >0
        // s ==t  : =0
        // s < t  : <0
        if (spath != null && tpath == null) {
            return 1;
        }
        if (spath == null && tpath != null) {
            return -1;
        }

        if (spath != null && tpath != null) {
            return spath.compareTo(tpath);
        }
        return 0;
    }
}
