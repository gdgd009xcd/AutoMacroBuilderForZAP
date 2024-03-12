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
public class CastUtils {

    /**
     * @param <T>
     * @param obj
     * @return
     */
    @SuppressWarnings({"unchecked"})
    public static <T> T castToType(Object obj) {
        return (T) obj;
    }

    public static <T> T castToType(Class<T> clazz, Object obj) {
        if (clazz.isAssignableFrom(obj.getClass())) {
            return clazz.cast(obj);
        }
        return null;
    }
}
