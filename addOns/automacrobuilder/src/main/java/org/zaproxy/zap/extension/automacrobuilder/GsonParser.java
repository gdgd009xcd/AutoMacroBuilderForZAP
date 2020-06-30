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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** @author daike */
public class GsonParser {
    private static Logger logger4j = LogManager.getLogger();

    enum EventType {
        NONE,
        START_OBJECT,
        END_OBJECT,
        START_ARRAY,
        END_ARRAY,
        BOOLEAN,
        NUMBER,
        STRING,
        NULL,
    }

    /**
     * @param element
     * @param listener
     * @return
     */
    public boolean elementLoopParser(JsonElement element, GsonParserListener listener) {
        boolean noerror = true;
        int level = 0;
        ParmGenStack<GsonIterator> itstack = new ParmGenStack<>();
        String kname = null;

        GsonIterator.ElmType currentelmtype = GsonIterator.ElmType.PRIMITIVE;
        GsonIterator git = null;

        do {
            try {
                if (element != null) {

                    if (element.isJsonArray()) {
                        JsonArray jarray = element.getAsJsonArray();
                        git = new GsonIterator(kname, jarray.iterator());
                        itstack.push(git);
                        level++;
                        noerror =
                                listener.receiver(
                                        git, GsonParser.EventType.START_ARRAY, kname, null, level);

                    } else if (element.isJsonObject()) {
                        JsonObject jobj = element.getAsJsonObject();
                        git = new GsonIterator(kname, jobj.entrySet());
                        itstack.push(git);
                        level++;
                        noerror =
                                listener.receiver(
                                        git, GsonParser.EventType.START_OBJECT, kname, null, level);

                    } else if (element.isJsonNull()) {

                        noerror =
                                listener.receiver(
                                        git, GsonParser.EventType.NULL, kname, null, level);
                    } else if (element.isJsonPrimitive()) {
                        JsonPrimitive jprim = element.getAsJsonPrimitive();
                        if (jprim.isBoolean()) {
                            Boolean b = jprim.getAsBoolean();
                            noerror =
                                    listener.receiver(
                                            git, GsonParser.EventType.BOOLEAN, kname, b, level);

                        } else if (jprim.isNumber()) {
                            Number numval = jprim.getAsNumber();
                            noerror =
                                    listener.receiver(
                                            git, GsonParser.EventType.NUMBER, kname, numval, level);

                        } else if (jprim.isString()) {
                            String s = jprim.getAsString();
                            noerror =
                                    listener.receiver(
                                            git, GsonParser.EventType.STRING, kname, s, level);
                        }
                    }
                }
                git = itstack.getCurrent();
                if (git != null) {
                    if (!git.hasNext()) { // end of array or object list

                        GsonParser.EventType etype = GsonParser.EventType.NONE;
                        if (currentelmtype == GsonIterator.ElmType.ARRAY) {
                            etype = GsonParser.EventType.END_ARRAY;
                        } else {
                            etype = GsonParser.EventType.END_OBJECT;
                        }
                        noerror = listener.receiver(git, etype, git.getKeyName(), null, level);
                        itstack.pop();
                        git = itstack.getCurrent();
                        if (git != null) {
                            currentelmtype = git.getElmType();
                        }
                        level--;
                    }
                    if (git != null && git.hasNext()) {
                        currentelmtype = git.getElmType();
                        GsonEntry jent = git.next();
                        if (jent.hasKey()) {
                            kname = jent.getKey();
                        } else {
                            kname = null;
                        }
                        element = jent.getJsonElement();
                    } else {
                        kname = null;
                        element = null;
                    }
                }
            } catch (Exception e) {
                logger4j.error("Exception at elementLoopParser", e);
                noerror = false;
            }

            if (!noerror) break;

        } while (itstack.size() > 0);

        return noerror;
    }
}
