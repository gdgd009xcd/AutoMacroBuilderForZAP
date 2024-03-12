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

import java.io.File;
import java.util.Optional;

/** @author gdgd009xcd */
public class FileInfo {

    private String dirname;
    private String basename;
    private String dirsep;
    private String suffix;
    private String dot;
    private String prefix;

    FileInfo(String fullfilename) {
        File file = new File(fullfilename);

        String fileSep = File.separator;

        dirname = getNoNullString(file.getParent());
        basename = getNoNullString(file.getName());
        suffix = getExtensionByStringHandling(basename);
        prefix = getPrefixByStringHandling(basename);

        dirsep = dirname.length() > 0 ? fileSep : "";

        dot = basename.contains(".") ? "." : "";
    }

    public String getDirName() {
        return dirname;
    }

    public String getBaseName() {
        return basename;
    }

    public String getPrefix() {
        return prefix;
    }

    public String getSuffix() {
        return suffix;
    }

    public String getFullFileName() {
        String fullname = dirname + dirsep + prefix + dot + suffix;

        return fullname;
    }

    public void setPrefix(String pstr) {
        Optional<String> optstr = Optional.ofNullable(pstr);
        prefix = optstr.orElse("");
    }

    public void setSuffix(String pstr) {
        Optional<String> optstr = Optional.ofNullable(pstr);
        suffix = optstr.orElse("");
    }

    private String getNoNullString(String maybenullstr) {
        Optional<String> ostr = Optional.ofNullable(maybenullstr);
        return ostr.orElse("");
    }

    private String getExtensionByStringHandling(String filename) {
        // 1) ofNullable() : if filename is not null, then filter method is called. otherwise return
        // Optional.empty().
        // 2) .filter(): if f.contains(".") is true, then map method called. otherwise return
        // Optional.empty().
        // 3) .map():  if f is not null then call f.substring == prefix return.
        Optional<String> optsuffix =
                Optional.ofNullable(filename)
                        .filter(f -> f.contains("."))
                        .map(f -> f.substring(filename.lastIndexOf(".") + 1));

        String suffix = optsuffix.orElse("");
        return suffix;
    }

    private String getPrefixByStringHandling(String filename) {

        Optional<String> optprefix =
                Optional.ofNullable(filename)
                        .map(
                                f ->
                                        f.substring(
                                                0,
                                                filename.lastIndexOf(".") > 0
                                                        ? filename.lastIndexOf(".")
                                                        : filename.length()))
                        .filter(f -> f.contains(".") == false);

        String prefix = optprefix.orElse("");
        return prefix;
    }
}
