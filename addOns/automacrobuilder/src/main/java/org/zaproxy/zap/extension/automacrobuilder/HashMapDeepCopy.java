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

import static org.zaproxy.zap.extension.automacrobuilder.CastUtils.castToType;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/** @author gdgd009xcd */
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
    private static <K extends DeepClone, V extends DeepClone> Map<K, V> hashMapDeepCopyKVClone(
            Map<K, V> src, Map<K, V> dest) {

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
    private static <K extends DeepClone, V> Map<K, V> hashMapDeepCopyKClone(
            Map<K, V> src, Map<K, V> dest) {
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
    private static <K, V extends DeepClone> Map<K, V> hashMapDeepCopyVClone(
            Map<K, V> src, Map<K, V> dest) {
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
    private static <K, V> Map<K, V> hashMapDeepCopyPrimitive(Map<K, V> src, Map<K, V> dest) {

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
    private static <String, V extends DeepClone> Map<String, V> hashMapDeepCopyStrK(
            Map<String, V> src, Map<String, V> dest) {
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
    public static Map<String, String> hashMapDeepCopyStrKStrV(Map<String, String> src) {
        if (src == null) return null;
        Map<String, String> dest = new HashMap<>();
        return hashMapDeepCopyPrimitive(src, dest);
    }

    /**
     * Copy {@code HashMap<String, ParmGenHeader>} String is immutable ParmGenHeader has clone()
     *
     * @param src {@code HashMap<String, ParmGenHeader>}
     * @return {@code HashMap<String, ParmGenHeader>}
     */
    public static Map<String, ParmGenHeader> hashMapDeepCopyStrKParmGenHeaderV(
            Map<String, ParmGenHeader> src) {
        if (src == null) return null;
        Map<String, ParmGenHeader> dest = new HashMap<String, ParmGenHeader>();
        return hashMapDeepCopyStrK(src, dest);
    }
    /**
     * Copy {@code HashMap<UUID, ParmGenTrackParam>} UUID is immutable, ParmGenTrackParam has
     * clone()
     *
     * @param src {@code HashMap<UUID, ParmGenTrackParam>}
     * @return {@code HashMap<UUID, ParmGenTrackParam>}
     */
    public static Map<UUID, ParmGenTrackingParam> hashMapDeepCopyUuidKParmGenTrackingParamV(
            Map<UUID, ParmGenTrackingParam> src) {
        if (src == null) return null;
        Map<UUID, ParmGenTrackingParam> dest = new HashMap<>();
        return hashMapDeepCopyVClone(src, dest);
    }

    /**
     * Copy {@code HashMap<ParmGenTokenKey,Integer>} ParmGenTokenKey has clone(). Integer is
     * immutable.
     *
     * @param src
     * @return {@code HashMap<ParmGenTokenKey, Integer>}
     */
    public static Map<ParmGenTokenKey, Integer> hashMapDeepCopyParmGenTokenKeyKIntegerV(
            Map<ParmGenTokenKey, Integer> src) {
        if (src == null) return null;
        Map<ParmGenTokenKey, Integer> dest = new HashMap<>();
        return hashMapDeepCopyKClone(src, dest);
    }

    /**
     * copy {@code HashMap<ParmGenTokenKey, ParmGenTokenValue>}
     *
     * @param src
     * @return {@code HashMap<ParmGenTokenKey, ParmGenTokenValue>}
     */
    public static Map<ParmGenTokenKey, ParmGenTokenValue> hashMapDeepCopyParmGenHashMapSuper(
            Map<ParmGenTokenKey, ParmGenTokenValue> src) {
        if (src == null) return null;
        Map<ParmGenTokenKey, ParmGenTokenValue> dest = new HashMap<>();
        return hashMapDeepCopyKVClone(src, dest);
    }

    /**
     * copy src {@code HashMap<ParmGenTokenKey, ParmGenTokenValue>} to specified dest
     *
     * @param src
     * @param dest
     * @return
     */
    public static Map<ParmGenTokenKey, ParmGenTokenValue> hashMapDeepElementCloneParmGenHashMap(
            Map<ParmGenTokenKey, ParmGenTokenValue> src,
            Map<ParmGenTokenKey, ParmGenTokenValue> dest) {
        if (src == null) return dest;
        return hashMapDeepCopyKVClone(src, dest);
    }

    /**
     * create new copy from src {@code Map<Integer, PRequestResponse>}
     *
     * @param src
     * @return
     */
    public static Map<Integer, PRequestResponse> hashMapDeepCopySaveList(
            Map<Integer, PRequestResponse> src) {
        if (src == null) return null;
        Map<Integer, PRequestResponse> dest = new HashMap<>();
        return hashMapDeepCopyVClone(src, dest);
    }
}
