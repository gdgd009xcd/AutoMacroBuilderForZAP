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

import java.util.List;

/**
 * InterfaceDoAction
 *
 * @author gdgd009xcd
 */
public interface InterfaceDoAction {
    /**
     * start action (synchronized)
     *
     * <PRE>
     * This function is "synchronized" called  where:
     *      synchronized OneThreadProcessor getProcess(InterfaceDoActionProvider provider)
     * new Instance:
     *     public OneThreadProcessor(ThreadManager tm, Thread th, InterfaceDoAction doaction)
     * RECYCLED    :
     *     public void setNewThread(Thread th)
     *
     * purpose: do  initiatize or copy fields... and return <b>action list</b>.
     * <b>action list</b>:  this is list of InterfaceAction.  The InterfaceAction will be called
     * with the number specified by InterfaceDoActionProvider.getActionNo()
     *
     * </PRE>
     *
     * @param tm
     * @param otp
     * @return
     */
    List<InterfaceAction> startAction(ThreadManager tm, OneThreadProcessor otp);

    /**
     * {@code List<InterfaceAction>} getActionList();
     *
     * <PRE>
     * end action (synchronized)
     * This function is "synchronized" called  where:
     *      synchronized void endProcess(OneThreadProcessor p, InterfaceDoAction action)
     * purpose: do some result save/update or post-processing etc... after startAction has done.
     *
     * </PRE>
     *
     * @param tm
     * @param otp
     * @return
     */
    InterfaceEndAction endAction(ThreadManager tm, OneThreadProcessor otp);
}
