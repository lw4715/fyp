import org.apache.batik.swing.JSVGCanvas;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class SVGApplication {

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

    protected JFrame frame;
    protected JTextArea label = new JTextArea();
    protected JSVGCanvas svgCanvas = new JSVGCanvas();

    public SVGApplication(JFrame f) {
        frame = f;
    }

    public JComponent createComponents(String filename) {
        final JPanel panel = new JPanel(new BorderLayout());

        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        label.setText("File saved at: " + filename);
        label.setColumns(70);
        label.setRows(3);
        label.setEditable(false);
        p.add(label);
        panel.add("North", p);
        panel.add("Center", svgCanvas);
        svgCanvas.setURI("file:" + filename);

        JButton helpBtn = new JButton("Help");
        helpBtn.setActionCommand("Help");
        helpBtn.addActionListener(new ButtonClickListener());

        p.add(helpBtn, Panel.RIGHT_ALIGNMENT);
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
                    label.setText("Sample diagram:\n" +
                            "Red boxes - strategic results (isCulprit), Yellow boxes - operational results, Blue boxes - technical results\n" +
                            "Rules are labelled at arrows, arrow direction indicates direction of derivation");
                    break;
                default:
                    SVGApplication.displayFile("img/" + command);
            }
        }
    }
}