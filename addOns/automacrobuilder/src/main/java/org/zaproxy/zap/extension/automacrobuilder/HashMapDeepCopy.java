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

import static org.zaproxy.zap.extension.automacrobuilder.CastUtils.castToType;

import java.util.HashMap;
import java.util.UUID;

/** @author daike */
class HashMapDeepCopy {

    /**
     * {@literal HashMap<K extends DeepClone(has public clone()), V extends DeepClone> deep copy}
     *
     * @param {@code <K>}
     * @param {@code <V>}
     * @param src
     * @param dest
     * @return {@code HashMap<K,V>}
     */
    private static <K extends DeepClone, V extends DeepClone> HashMap<K, V> hashMapDeepCopyKVClone(
            HashMap<K, V> src, HashMap<K, V> dest) {

        if (src != null && dest != null) {
            src.entrySet()
                    .forEach(
                            ent -> {
                                dest.put(
                                        castToType(ent.getKey().clone()),
                                        castToType(ent.getValue().clone()));
                            });
        }

        return dest;
    }

    /**
     * {@literal HashMap<K extends DeepClone, V> deep copy}
     *
     * @param {@code <K>}
     * @param {@code <V>}
     * @param src copy from
     * @param dest copy to
     * @return {@code HashMap<K,V>}
     */
    private static <K extends DeepClone, V> HashMap<K, V> hashMapDeepCopyKClone(
            HashMap<K, V> src, HashMap<K, V> dest) {
        if (src != null && dest != null) {
            src.entrySet()
                    .forEach(
                            ent -> {
                                dest.put(castToType(ent.getKey().clone()), ent.getValue());
                            });
        }
        return dest;
    }

    /**
     * {@literal HashMap<K, V extends DeepClone> deep copy}
     *
     * @param {@code <K>}
     * @param {@code <V>}
     * @param src copy from
     * @param dest copy to
     * @return {@code HashMap<K,V>}
     */
    private static <K, V extends DeepClone> HashMap<K, V> hashMapDeepCopyVClone(
            HashMap<K, V> src, HashMap<K, V> dest) {
        if (src != null && dest != null) {
            src.entrySet()
                    .forEach(
                            ent -> {
                                dest.put(ent.getKey(), castToType(ent.getValue().clone()));
                            });
        }
        return dest;
    }

    /**
     * {@code HashMap<K, V>} copy(Both K and V param is Primitive or no DeepClone (which has No
     * Cloneable method) variants.)
     *
     * @param {@code <K>}
     * @param {@code <V>}
     * @param src copy from
     * @param dest copy to
     * @return {@code HashMap<K,V>}
     */
    private static <K, V> HashMap<K, V> hashMapDeepCopyPrimitive(
            HashMap<K, V> src, HashMap<K, V> dest) {

        if (src != null && dest != null) {
            src.entrySet()
                    .forEach(
                            ent -> {
                                dest.put(ent.getKey(), ent.getValue());
                            });
        }
        return dest;
    }

    /**
     * {@literal HashMap<String, V extends DeepClone> deep copy}
     *
     * @param {@code <V>}
     * @param src copy from
     * @param dest to which copy src
     * @return {@code HashMap<String,V extends DeepClone>}
     */
    private static <String, V extends DeepClone> HashMap<String, V> hashMapDeepCopyStrK(
            HashMap<String, V> src, HashMap<String, V> dest) {
        return hashMapDeepCopyVClone(src, dest);
    }

    /**
     * {@code HashMap<String, String>} copy( that is same as {@code HashMap<String,String>}.clone().
     * because String is immutable. In other words String is "final fixed(unchangable)" object.)
     *
     * @param {@code <V>}
     * @param src copy from
     * @return {@code HashMap<String,String>} dest to which copy src
     */
    public static HashMap<String, String> hashMapDeepCopyStrKStrV(HashMap<String, String> src) {
        if (src == null) return null;
        HashMap<String, String> dest = new HashMap<>();
        return hashMapDeepCopyPrimitive(src, dest);
    }

    /**
     * Copy {@code HashMap<String, ParmGenHeader>} String is immutable ParmGenHeader has clone()
     *
     * @param src {@code HashMap<String, ParmGenHeader>}
     * @return {@code HashMap<String, ParmGenHeader>}
     */
    public static HashMap<String, ParmGenHeader> hashMapDeepCopyStrKParmGenHeaderV(
            HashMap<String, ParmGenHeader> src) {
        if (src == null) return null;
        HashMap<String, ParmGenHeader> dest = new HashMap<String, ParmGenHeader>();
        return hashMapDeepCopyStrK(src, dest);
    }
    /**
     * Copy {@code HashMap<UUID, ParmGenTrackParam>} UUID is immutable, ParmGenTrackParam has
     * clone()
     *
     * @param src {@code HashMap<UUID, ParmGenTrackParam>}
     * @return {@code HashMap<UUID, ParmGenTrackParam>}
     */
    public static HashMap<UUID, ParmGenTrackingParam> hashMapDeepCopyUuidKParmGenTrackingParamV(
            HashMap<UUID, ParmGenTrackingParam> src) {
        if (src == null) return null;
        HashMap<UUID, ParmGenTrackingParam> dest = new HashMap<>();
        return hashMapDeepCopyVClone(src, dest);
    }

    /**
     * Copy {@code HashMap<ParmGenTokenKey,Integer>} ParmGenTokenKey has clone(). Integer is
     * immutable.
     *
     * @param src
     * @return {@code HashMap<ParmGenTokenKey, Integer>}
     */
    public static HashMap<ParmGenTokenKey, Integer> hashMapDeepCopyParmGenTokenKeyKIntegerV(
            HashMap<ParmGenTokenKey, Integer> src) {
        if (src == null) return null;
        HashMap<ParmGenTokenKey, Integer> dest = new HashMap<>();
        return hashMapDeepCopyKClone(src, dest);
    }

    /**
     * copy {@code HashMap<ParmGenTokenKey, ParmGenTokenValue>}
     *
     * @param src
     * @return {@code HashMap<ParmGenTokenKey, ParmGenTokenValue>}
     */
    public static HashMap<ParmGenTokenKey, ParmGenTokenValue> hashMapDeepCopyParmGenHashMapSuper(
            HashMap<ParmGenTokenKey, ParmGenTokenValue> src) {
        if (src == null) return null;
        HashMap<ParmGenTokenKey, ParmGenTokenValue> dest = new HashMap<>();
        return hashMapDeepCopyKVClone(src, dest);
    }

    public static HashMap<ParmGenTokenKey, ParmGenTokenValue> hashMapDeepElementCloneParmGenHashMap(
            HashMap<ParmGenTokenKey, ParmGenTokenValue> src,
            HashMap<ParmGenTokenKey, ParmGenTokenValue> dest) {
        if (src == null) return dest;
        return hashMapDeepCopyKVClone(src, dest);
    }
}
