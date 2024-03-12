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

/** @author gdgd009xcd */
public interface DeepClone extends Cloneable {
    //
    //
    // Correct example:
    //
    //    class crazyobject implements DeepClone{
    //
    //    ...
    //        {@literal @}Override
    //        public crazyobject clone() { // return this Type object
    //                                    //which is not java.lang.ObjectType.
    //               crazyobject nobj =  (crazyobject) super.clone();
    //               // !! you must always use super.clone().
    //               // also inherit class must use super.clone.
    //               // DO NOT USE new XX constructor in clone().
    //               // if you use constructor then
    //               // you will get java.lang.ClassCastException attack.
    //               nobj.optlist = ListDeepCopy.listDeepCopy(this.optlist);// member of this class
    //               return nobj;
    //        }
    //
    public Object clone();
}
