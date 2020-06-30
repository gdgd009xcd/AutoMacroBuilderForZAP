/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder;

/**
 *
 * @author daike
 */
public interface InterfaceClientDependantMessage<T> {
    
    public T getClientDpendMessage();
    
    public void setClientDependMessage(T t);
    
    public String getHost();
    
    public int getPort();
    
    public boolean isSSL();
    
    public byte[] getRequestByte();
    
    public byte[] getResponseByte();
    
    public Encode getRequestEncode();
    
    public Encode getResponseEncode();
    
}
