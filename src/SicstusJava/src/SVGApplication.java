import org.apache.batik.swing.JSVGCanvas;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class SVGApplication {

    private static final String fileTextArea = "File saved at: ";
    private static final String RELOAD = "Reload";
    private static JFrame f;

    static void displayFile(String filename) {
        f = new JFrame("Derivation");
        f.setLayout(new BoxLayout(f.getContentPane(), BoxLayout.Y_AXIS));
        SVGApplication app = new SVGApplication(f);
        f.getContentPane().add(app.createComponents(filename));
        f.setSize(1200, 800);
        f.setVisible(true);
    }

    private JTextArea textArea;
    private JSVGCanvas svgCanvas;
    private JButton helpBtn;
    String filename;

    public SVGApplication(JFrame f) {
        textArea = new JTextArea();
        svgCanvas = new JSVGCanvas();

        Action zoomInAction =
                svgCanvas.getActionMap().get(JSVGCanvas.ZOOM_IN_ACTION);
        Action zoomOutAction =
                svgCanvas.getActionMap().get(JSVGCanvas.ZOOM_OUT_ACTION);

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
        final JPanel panel = new JPanel(new BorderLayout());

        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        textArea.setText(fileTextArea + filename);
        textArea.setColumns(80);
        textArea.setRows(7);
        textArea.setEditable(false);
        svgCanvas.setURI("file:" + filename);

        helpBtn = new JButton("Help");
        helpBtn.setActionCommand("Help");
        helpBtn.addActionListener(new ButtonClickListener());

        JButton reloadBtn = new JButton(RELOAD);
        reloadBtn.setActionCommand(RELOAD);
        reloadBtn.addActionListener(new ButtonClickListener());

        p.add(textArea);
        p.add(reloadBtn);
        p.add(helpBtn, Panel.RIGHT_ALIGNMENT);

        panel.add("Center", svgCanvas);
        panel.add("South", p);

        return panel;
    }

    private class ButtonClickListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String command = e.getActionCommand();
            switch (command) {
                case "Help":
                    svgCanvas.setURI("file:img/_sample.svg");
                    textArea.setText("Sample diagram:\n" +
                            "Red boxes - strategic results (isCulprit), Yellow boxes - operational results, Blue boxes - technical results\n" +
                            "Rules are labelled at arrows, arrow direction indicates direction of derivation");
                    helpBtn.setText("Back to diagram");
                    helpBtn.setActionCommand("Back");
                    break;
                case "Back":
                    svgCanvas.setURI("file:" + filename);
                    textArea.setText(fileTextArea + filename);
                    helpBtn.setText("Help");
                    helpBtn.setActionCommand("Help");
                    break;
                case RELOAD:
                    f.dispose();
                    displayFile(filename);
                    break;
                default:
                    displayFile("img/" + command);
            }
        }
    }
}