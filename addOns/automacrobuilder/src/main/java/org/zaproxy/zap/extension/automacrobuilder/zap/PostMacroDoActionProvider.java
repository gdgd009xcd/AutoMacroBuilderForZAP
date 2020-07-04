package org.zaproxy.zap.extension.automacrobuilder.zap;

import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.automacrobuilder.InterfaceDoAction;
import org.zaproxy.zap.extension.automacrobuilder.InterfaceDoActionProvider;

public class PostMacroDoActionProvider implements InterfaceDoActionProvider {
    private PostMacroDoAction doactioninstance = new PostMacroDoAction();

    public void setParameters(
            StartedActiveScanContainer acon, HttpMessage msg, int initiator, HttpSender sender) {
        doactioninstance.setParameters(acon, msg, initiator, sender);
    }

    @Override
    public int getSequnceNo() {
        return 1;
    }

    @Override
    public int getActionNo() {
        return 0;
    }

    @Override
    public InterfaceDoAction getDoActionInstance() {
        return this.doactioninstance;
    }
}
