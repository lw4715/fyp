import org.apache.batik.swing.JSVGCanvas;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class SVGApplication {

    private static final String FILE_TEXT = "File saved at: ";
    private static final String RELOAD = "Reload";
    private static JFrame f;
    private JTextArea textArea;
    private JSVGCanvas svgCanvas;
    private JButton helpBtn;
    private String filename;

    static void displayFile(String filename) {
        SVGApplication.f = new JFrame("Derivation");
        SVGApplication.f.setLayout(new BoxLayout(SVGApplication.f.getContentPane(), BoxLayout.Y_AXIS));
        SVGApplication app = new SVGApplication(SVGApplication.f);
        SVGApplication.f.getContentPane().add(app.createComponents(filename));
        SVGApplication.f.setSize(1200, 800);
        SVGApplication.f.setVisible(true);
    }

    public SVGApplication(JFrame f) {
        this.textArea = new JTextArea();
        this.svgCanvas = new JSVGCanvas();

        Action zoomInAction =
                this.svgCanvas.getActionMap().get(JSVGCanvas.ZOOM_IN_ACTION);
        Action zoomOutAction =
                this.svgCanvas.getActionMap().get(JSVGCanvas.ZOOM_OUT_ACTION);

        JButton zoomInButton = new JButton("Zoom in (Ctrl+I)");
        zoomInButton.addActionListener(zoomInAction);
        JButton zoomOutButton = new JButton("Zoom out (Ctrl+O)");
        zoomOutButton.addActionListener(zoomOutAction);

        JPanel btnPanel = new JPanel();
        btnPanel.setLayout(new FlowLayout());
        btnPanel.add(zoomInButton);
        btnPanel.add(zoomOutButton);
        btnPanel.add(new JLabel("(Press arrow keys to move)"));
        f.getContentPane().add(btnPanel);
    }

    public JComponent createComponents(String filename) {
        this.filename = filename;
        JPanel panel = new JPanel(new BorderLayout());

        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        this.textArea.setText(SVGApplication.FILE_TEXT + filename);
        this.textArea.setColumns(80);
        this.textArea.setRows(7);
        this.textArea.setEditable(false);
        this.svgCanvas.setURI("file:" + filename);

        this.helpBtn = new JButton("Help");
        this.helpBtn.setActionCommand("Help");
        this.helpBtn.addActionListener(new ButtonClickListener());

        JButton reloadBtn = new JButton(SVGApplication.RELOAD);
        reloadBtn.setActionCommand(SVGApplication.RELOAD);
        reloadBtn.addActionListener(new ButtonClickListener());

        p.add(this.textArea);
        p.add(reloadBtn);
        p.add(this.helpBtn, Panel.RIGHT_ALIGNMENT);

        panel.add("Center", this.svgCanvas);
        panel.add("South", p);

        return panel;
    }

    private class ButtonClickListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String command = e.getActionCommand();
            switch (command) {
                case "Help":
                    SVGApplication.this.svgCanvas.setURI("file:img/_sample.svg");
                    SVGApplication.this.textArea.setText("Sample diagram:\n" +
                            "Red boxes - strategic results (isCulprit), Yellow boxes - operational results, Blue boxes - technical results\n" +
                            "Rules are labelled at arrows, arrow direction indicates direction of derivation");
                    SVGApplication.this.helpBtn.setText("Back to diagram");
                    SVGApplication.this.helpBtn.setActionCommand("Back");
                    break;
                case "Back":
                    SVGApplication.this.svgCanvas.setURI("file:" + SVGApplication.this.filename);
                    SVGApplication.this.textArea.setText(SVGApplication.FILE_TEXT + SVGApplication.this.filename);
                    SVGApplication.this.helpBtn.setText("Help");
                    SVGApplication.this.helpBtn.setActionCommand("Help");
                    break;
                case SVGApplication.RELOAD:
                    SVGApplication.f.dispose();
                    SVGApplication.displayFile(SVGApplication.this.filename);
                    break;
                default:
                    SVGApplication.displayFile("img/" + command);
            }
        }
    }
}