package org.zaproxy.zap.extension.automacrobuilder.zap;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.network.HttpMessage;

public class CustomScannerListener implements org.parosproxy.paros.core.scanner.ScannerListener {
    @Override
    public void scannerComplete(int id) {

    }

    @Override
    public void hostNewScan(int id, String hostAndPort, HostProcess hostThread) {

    }

    @Override
    public void hostProgress(int id, String hostAndPort, String msg, int percentage) {

    }

    @Override
    public void hostComplete(int id, String hostAndPort) {

    }

    @Override
    public void alertFound(Alert alert) {

    }

    @Override
    public void notifyNewMessage(HttpMessage msg) {

    }
}
