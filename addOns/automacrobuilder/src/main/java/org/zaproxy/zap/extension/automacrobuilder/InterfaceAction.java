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

/**
 * InterfaceAction
 *
 * @author gdgd009xcd
 */
public interface InterfaceAction {
    /**
     *
     *
     * <PRE>
     * main Action concurrently  called  per thread by THreadManager.
     * if this action return true, then InterfaceEndAction will "synchronized" called
     * return true: endAction execute.
     *       false:  nothing to do endAction
     * </PRE>
     *
     * @param tm
     * @param otp
     * @return
     */
    boolean action(ThreadManager tm, OneThreadProcessor otp);
}
