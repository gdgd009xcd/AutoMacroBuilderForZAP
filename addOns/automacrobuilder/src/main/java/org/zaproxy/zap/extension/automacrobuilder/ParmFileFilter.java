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
import java.util.ResourceBundle;
import javax.swing.filechooser.FileFilter;

/** @author gdgd009xcd */
public class ParmFileFilter extends FileFilter {

    private static final ResourceBundle bundle = ResourceBundle.getBundle("burp/Bundle");

    private static final String fileExtName = "json";

    public boolean accept(File f) {
        /* ディレクトリなら無条件で表示する */
        if (f.isDirectory()) {
            return true;
        }

        /* 拡張子を取り出し、jsonだったら表示する */
        String ext = getExtension(f);
        if (ext != null) {
            if (ext.equals(fileExtName)) {
                return true;
            } else {
                return false;
            }
        }

        return false;
    }

    public String getDescription() {
        return bundle.getString("ParmFileFilter.Description.text");
    }

    /* 拡張子を取り出す */
    private String getExtension(File f) {
        String ext = null;
        String filename = f.getName();
        int dotIndex = filename.lastIndexOf('.');

        if ((dotIndex > 0) && (dotIndex < filename.length() - 1)) {
            ext = filename.substring(dotIndex + 1).toLowerCase();
        }

        return ext;
    }

    /**
     * get String = "." + fileExtName
     *
     * @return "." + fileExtName
     */
    @Override
    public String toString() {
        return "." + fileExtName;
    }
}
