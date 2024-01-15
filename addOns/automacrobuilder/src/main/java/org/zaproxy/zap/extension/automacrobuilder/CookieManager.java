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

import java.net.CookiePolicy;
import java.net.CookieStore;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** @author gdgd009xcd */
public class CookieManager implements DeepClone {
    private static final org.apache.logging.log4j.Logger LOGGER4J =
            org.apache.logging.log4j.LogManager.getLogger();
    private java.net.CookieManager manager = null;
    private CookieStore cookiestore = null;
    private Set<URI> originalURIs;

    CookieManager() {
        init();
    }

    private void init() {
        manager = new java.net.CookieManager();
        manager.setCookiePolicy(CookiePolicy.ACCEPT_NONE);
        cookiestore = manager.getCookieStore();
        originalURIs = new HashSet<>();
    }

    private URI getURI(String domain, String path, boolean isSSL) {
        try {
            String url = (isSSL ? "https://" : "http://") + domain + path;
            URI uri = new URI(url);
            // System.out.println("getURI: [" + uri.toString() + " scheme[" +  uri.getScheme() +  "]
            // host[" + uri.getHost() + "] path[" + uri.getPath() + "]");
            return uri;
        } catch (URISyntaxException ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
        return null;
    }


    public void removeAll() {
        cookiestore.removeAll();originalURIs.clear();
    }

    /**
     * Parse Set-Cookie or Set-Cookie2 header and stores it in cookiestore.
     *
     * @param hostName name or IP address in URI
     * @param path pathName in URI
     * @param setCookieHeader
     * @return parsed List<HttpCookie>
     */
    public List<HttpCookie> parse(String hostName, String path, String setCookieHeader) {
        List<HttpCookie> parsedcookies = HttpCookie.parse(setCookieHeader);
        if (parsedcookies != null && parsedcookies.size() > 0) {
            URI uri =
                    getURI(
                            hostName, path,

                            true); // SSL attribute is ignored when cookie values ​​are added to
            if (uri != null) {
                String defaultPath = extractDefaultPath(path);
                originalURIs.add(uri);
                //
                // Description of Cookie Attributes
                //
                // * domain
                //   specified:
                //     cookie is sent specified domain or subdomain of it.
                //     the domain attribute must be a domain containing the
                //     current host name, so, only same as host or subdomain can be specified.
                //     (ex: hostname example.com  domain=example.com or domain=www.example.com)
                //   Not specified:
                //     If domain attribute is not specified, the cookie is sent only to the host that sent Set-Cookie.
                //
                // * path
                //   specified:
                //     cookie is sent to the request path which prefix matches the path value.
                //
                //   Not specified:
                //     defaultPath is assigned as the path value. defaultPath is  directory portion of request-uri.
                //     ex1. uri=http://test.com/shared/lib/index.php
                //          defaultPath = /shared/lib
                //     ex2. uri=http://test.com/index.php
                //          defaultPath = /
                //     ex3. uri=http://test.com/
                //          defaultPath = /
                //
                //
                for (HttpCookie hc : parsedcookies) {
                    String pathProp = hc.getPath();
                    if (pathProp == null || pathProp.isEmpty()) {
                        hc.setPath(defaultPath);
                    }
                    cookiestore.add(uri, hc);
                }
                return parsedcookies;
            }
        }
        return null;
    }


    public List<HttpCookie> get(String domain, String path, boolean isSSL) {
        URI uri =
                getURI(
                        domain, path,
                        isSSL); // isSSL : secure attribute is ignored in this get method.
        return get(uri);
    }

    public List<HttpCookie> get(URI uri) {
        String path = uri.getPath();
        try {
            // System.out.println("get: domain[" + domain + "] path[" + path + "] SSL:" +
            // (isSSL?"TRUE":"FALSE"));
            List<HttpCookie> rawresults = cookiestore.get(uri);
            LOGGER4J.debug("rawresults.size=" + rawresults.size());
            // cookiestore.get implementation ignores path attribute.
            // so, It is necessary to search the path attribute.
            ArrayList<HttpCookie> results = new ArrayList<>();
            for (HttpCookie hc : rawresults) {
                String hc_path = hc.getPath();
                if (hc_path != null && path != null) {
                    if (path.startsWith(hc_path)) {
                        results.add(hc);
                    }
                } else {
                    results.add(hc);
                }
            }
            return results;
        } catch (NullPointerException ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }
        return null;
    }

    public List<HttpCookie> getCookies() {
        return cookiestore.getCookies();
    }

    /**
     * getURIs always return [http://domain]. protocol always [http], path is "". The value returned
     * by the getURIs function is different from when it was added to the store. so I think
     * cookiestore's URI is something customized.
     *
     * @return List<URI>
     */
    @Deprecated
    private List<URI> getURIs() {
        return cookiestore.getURIs();
    }


    @Override
    public CookieManager clone() {
        try {
            CookieManager nobj = (CookieManager) super.clone();
            nobj.init();
            nobj.addCookieManager(this);
            return nobj;
        } catch (CloneNotSupportedException ex) {
            LOGGER4J.error(ex.getMessage(), ex);
        }

        return null;
    }


    /**
     * extract the default-path of Cookie path from request-path
     *
     * @param requestPath
     * @return default-path
     */
    public String extractDefaultPath(String requestPath) {
        if (requestPath == null || requestPath.isEmpty()) return "/";
        int endPos = requestPath.lastIndexOf("/");
        if (endPos > 0) {
            return requestPath.substring(0, endPos);
        }
        return "/";
    }

    public void addCookieManager(CookieManager cookieManager) {
        Set<URI> URIs = cookieManager.getOriginalURIs();
        if (URIs != null) {
            URIs.forEach(
                    uri -> {
                        List<HttpCookie> cookies = cookieManager.get(uri);
                        this.originalURIs.add(uri);
                        cookies.forEach(
                                cookie -> {
                                    this.cookiestore.add(
                                            uri,
                                            CastUtils.castToType(
                                                    cookie.clone())); // uri: immutable,
                                    // cookie has clone()
                                });
                    });
        }
    }

    public Set<URI> getOriginalURIs() {return this.originalURIs;}
}
