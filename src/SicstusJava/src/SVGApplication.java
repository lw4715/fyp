import org.apache.batik.swing.JSVGCanvas;

import javax.swing.*;
import java.awt.*;

public class SVGApplication {

    public static void main(String[] args) {
        // Create a new JFrame.


        // Add components to the frame.
        displayFile("img/apt1_china5.svg");
    }

    static void displayFile(String filename) {
        JFrame f = new JFrame("Derivation");
        SVGApplication app = new SVGApplication(f);
        f.getContentPane().add(app.createComponents(filename));
        f.setSize(1000, 800);
        f.setVisible(true);
    }

    // The frame.
    protected JFrame frame;

    // The "Load" button, which displays up a file chooser upon clicking.
//    protected JButton button = new JButton("Load...");

    // The status label.
    protected JLabel label = new JLabel();

    // The SVG canvas.
    protected JSVGCanvas svgCanvas = new JSVGCanvas();

    public SVGApplication(JFrame f) {
        frame = f;
    }

    public JComponent createComponents(String filename) {
        // Create a panel and add the button, status label and the SVG canvas.
        final JPanel panel = new JPanel(new BorderLayout());

        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        p.add(label);

        panel.add("North", p);
        panel.add("Center", svgCanvas);

        svgCanvas.setURI("file:" + filename);

        return panel;
    }
}