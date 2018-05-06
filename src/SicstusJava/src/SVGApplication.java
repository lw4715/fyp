import org.apache.batik.swing.JSVGCanvas;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class SVGApplication {

    private static final String fileTextArea = "File saved at: ";

    public static void main(String[] args) {
        displayFile("img/apt1_china5.svg");
    }

    static void displayFile(String filename) {
        JFrame f = new JFrame("Derivation");
        SVGApplication app = new SVGApplication(f);
        f.getContentPane().add(app.createComponents(filename));
        f.setSize(1200, 800);
        f.setVisible(true);
    }

    private JFrame frame;
    private JTextArea textArea = new JTextArea();
    private JSVGCanvas svgCanvas = new JSVGCanvas();
    private JButton helpBtn;
    String filename;

    public SVGApplication(JFrame f) {
        frame = f;
    }

    public JComponent createComponents(String filename) {
        this.filename = filename;
        final JPanel panel = new JPanel(new BorderLayout());

        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        textArea.setText(fileTextArea + filename);
        textArea.setColumns(80);
        textArea.setRows(7);
        textArea.setEditable(false);
        p.add(textArea);
        panel.add("North", p);
        panel.add("Center", svgCanvas);
        svgCanvas.setURI("file:" + filename);

        helpBtn = new JButton("Help");
        helpBtn.setActionCommand("Help");
        helpBtn.addActionListener(new ButtonClickListener());

        p.add(helpBtn, Panel.RIGHT_ALIGNMENT);
        panel.add("South", p);

        return panel;
    }

    private class ButtonClickListener implements ActionListener {
        private String previousURI;

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
                default:
                    SVGApplication.displayFile("img/" + command);
            }
        }
    }
}