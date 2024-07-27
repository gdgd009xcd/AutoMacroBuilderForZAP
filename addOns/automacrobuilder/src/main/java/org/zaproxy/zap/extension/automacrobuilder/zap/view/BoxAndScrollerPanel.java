package org.zaproxy.zap.extension.automacrobuilder.zap.view;

import javax.swing.*;
import java.awt.*;

@SuppressWarnings("serial")
public class BoxAndScrollerPanel extends JPanel {
    // create borderlayout for adding option input components in the future
    //  |-------------border layout PAGE_START--------------------|
    //  | |---------Box layout BoxLayout.Y_AXIS-----------------| |
    //  | | checkBox1 ------------------|                       | |
    //  | | checkBox2 ------------------|                       | |
    //  | |-----------------------------------------------------| |
    //  |-------------border layout PAGE_CENTER-------------------|
    //  | |---------------- JScrollPane ------------------------| |
    //  | |                                                     | |
    //  | |-----------------------------------------------------| |
    //  |---------------------------------------------------------|

    private JPanel boxPanel;
    private JScrollPane scroller;

    public BoxAndScrollerPanel() {
        super();
        initialize(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED,JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
    }

    public BoxAndScrollerPanel(int horizontalPolicy, int verticalPolicy) {
        super();
        initialize(horizontalPolicy, verticalPolicy);
    }

    private void initialize(int horizontalPolicy, int verticalPolicy) {
        // create borderlayout for total background
        BorderLayout boxAndScrollerBorderLayout = new BorderLayout();
        boxAndScrollerBorderLayout.setVgap(10);
        this.setLayout(boxAndScrollerBorderLayout);

        // create BoxLayout.Y=AXIS in PAGE_START
        boxPanel = new JPanel();
        boxPanel.setLayout(new BoxLayout(boxPanel, BoxLayout.PAGE_AXIS));
        // add BoxLayout to PAGE_START of Borderlayout JPanel
        this.add(boxPanel, BorderLayout.PAGE_START);

        // create JScrollPane in PAGE_CENTER
        scroller = new JScrollPane();
        scroller.setHorizontalScrollBarPolicy(horizontalPolicy);
        scroller.setVerticalScrollBarPolicy(verticalPolicy);
        scroller.setPreferredSize(new Dimension(400,400));
        scroller.setAutoscrolls(true);


        // add JScrolledPane to CENTER area of BorderLayout JPanel
        this.add(scroller, BorderLayout.CENTER);
    }

    public void addComponentToBoxPanelAtYaxis(Component compo) {
        boxPanel.add(compo);
    }

    public void setComponentToScroller(Component compo) {
        scroller.setViewportView(compo);
    }
}
