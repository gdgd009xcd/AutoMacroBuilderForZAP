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

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.CookieStore;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/** @author gdgd009xcd */
public class ParmGenCookieManager implements DeepClone {
    private CookieManager manager = null;
    private CookieStore cookiestore = null;

    ParmGenCookieManager() {
        init();
    }

    private void init() {
        manager = new CookieManager();
        manager.setCookiePolicy(CookiePolicy.ACCEPT_NONE);
        cookiestore = manager.getCookieStore();
    }

    private URI getURI(String domain, String path, boolean isSSL) {
        try {
            String url = (isSSL ? "https://" : "http://") + domain + path;
            URI uri = new URI(url);
            // System.out.println("getURI: [" + uri.toString() + " scheme[" +  uri.getScheme() +  "]
            // host[" + uri.getHost() + "] path[" + uri.getPath() + "]");
            return uri;
        } catch (URISyntaxException ex) {
            Logger.getLogger(ParmGenCookieManager.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * add cookie currently no used.
     *
     * @param domain
     * @param path
     * @param name
     * @param value
     * @param isSSL
     */
    public void add(String domain, String path, String name, String value, boolean isSSL) {
        URI uri = getURI(domain, path, isSSL);
        HttpCookie hcookie = new HttpCookie(name, value);
        hcookie.setDomain(domain);
        hcookie.setPath(path);
        hcookie.setSecure(isSSL);
        cookiestore.add(uri, hcookie);
    }

    public void removeAll() {
        cookiestore.removeAll();
    }

    public boolean remove(String domain, String path, String name) {
        URI uri = getURI(domain, path, false);
        HttpCookie hcookie = new HttpCookie(name, "");
        hcookie.setDomain(domain);
        hcookie.setPath(path);
        return cookiestore.remove(uri, hcookie);
    }

    /**
     * Parse Set-Cookie or Set-Cookie2 header and stores it in cookiestore.
     *
     * @param domain
     * @param path
     * @param cheader
     * @return parsed List<HttpCookie>
     */
    public List<HttpCookie> parse(String domain, String path, String cheader) {
        List<HttpCookie> parsedcookies = HttpCookie.parse(cheader);
        if (parsedcookies != null && parsedcookies.size() > 0) {
            URI uri =
                    getURI(
                            domain, "/",
                            true); // SSL attribute is ignored when cookie values ​​are added to
            // this cookie store.
            // Cookie値がこのCookieストアに追加される際、ここで指定したSSL属性は無視されます。
            // * The domain specified in the domain attribute must be a domain containing the
            // current host name, so, only same as host or subdomain can be specified.
            //   (ex: hostname example.com  domain=example.com or domain=www.example.com)
            // * Set-Cookieで指定されるドメイン属性は、現在のホスト名をふくんでいなくてはならない。つまりホストと同じかサブドメインのみ指定可能
            //  （例： host名 example.com  domain=example.com or domain=www.example.com）
            //   If domain attribute is not specified, the cookie is sent only to the host that sent
            // Set-Cookie.
            //   domain属性無指定の場合は、現在のホストにのみcookieは送信される。
            for (HttpCookie hc : parsedcookies) {
                String pathprop = hc.getPath();
                if (pathprop == null || pathprop.length() <= 0) {
                    hc.setPath(path);
                }
                cookiestore.add(uri, hc);
            }
            return parsedcookies;
        }
        return null;
    }

    public List<HttpCookie> get(URI uri) {
        return cookiestore.get(uri);
    }

    public List<HttpCookie> get(String domain, String path, boolean isSSL) {
        try {
            URI uri =
                    getURI(
                            domain, path,
                            isSSL); // isSSL : secure attribute is ignored in this get method.
            // System.out.println("get: domain[" + domain + "] path[" + path + "] SSL:" +
            // (isSSL?"TRUE":"FALSE"));
            List<HttpCookie> rawresults = cookiestore.get(uri);
            // cookiestore.get implimentation ignores path attribute.
            // so, It is necessary to search the path attribute.
            ArrayList<HttpCookie> results = new ArrayList<>();
            for (HttpCookie hc : rawresults) {
                String hc_path = hc.getPath();
                if (path.startsWith(hc_path)) {
                    results.add(hc);
                }
            }
            return results;
        } catch (NullPointerException ex) {
            Logger.getLogger(ParmGenCookieManager.class.getName()).log(Level.SEVERE, null, ex);
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
    public List<URI> getURIs() {
        return cookiestore.getURIs();
    }

    @Override
    public ParmGenCookieManager clone() {
        try {
            ParmGenCookieManager nobj = (ParmGenCookieManager) super.clone();
            nobj.init();

            List<URI> urilist = this.cookiestore.getURIs();
            if (urilist != null) {
                urilist.forEach(
                        uri -> {
                            List<HttpCookie> cookies = this.cookiestore.get(uri);
                            cookies.forEach(
                                    cookie -> {
                                        nobj.cookiestore.add(
                                                uri,
                                                CastUtils.castToType(
                                                        cookie.clone())); // uri: immutable,
                                        // cookie has clone()
                                    });
                        });
            }
            return nobj;
        } catch (CloneNotSupportedException ex) {
            Logger.getLogger(ParmGenCookieManager.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }
}
