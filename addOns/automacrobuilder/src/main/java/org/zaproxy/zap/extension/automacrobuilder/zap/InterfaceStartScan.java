/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.zaproxy.zap.extension.automacrobuilder.zap;

import org.zaproxy.zap.extension.ascan.ActiveScan;

/**
 * Interface for Zap ActiveScan
 *
 * @author daike
 */
public interface InterfaceStartScan {
    public ActiveScan startScan();
}
