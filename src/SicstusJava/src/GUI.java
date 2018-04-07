import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.stream.Stream;

class GUI {
    private final Utils utils;
    private JFrame mainFrame;
    private JLabel status;
    private JPanel panel1;
    private JPanel panel2;
    private JPanel panel3;
    private JPanel panel4;
    private JComboBox dropdown;
    private JTextField evidence;
    private JTextField attackName;
    private JTextArea currentEvidences;

    private static final String[] placeholderItem = {"Select from existing predicates"};

    private static final String[] techPredicates =
            {
                "highLevelSkill/1", "requireHighResource/1",
                "ipGeoloc/2", "geolocInCountry/2", "attackSourceIP/2",
                "spoofedIp/1", "sysLanguage/2", "firstLanguage/2",
                "languageInCode/2", "infraRegisteredIn/2", "infraUsed/2",
                "forBlackMarketUse/1", "infectionMethod/2",
                "controlAndCommandEasilyFingerprinted/1", "similarCCServer/2",
                "ccServer/2", "domainRegisteredDetails/3", "addressType/2",
                "simlarCodeObfuscation/2", "sharedCode/2", "malwareModifiedFrom/2",
                "specificConfigInMalware/1", "malwareUsedInAttack/2",
                "usesZeroDayVulnerabilities/1", "sophisticatedMalware/1", "specificTarget/1"
        };
    private static final String[] opPredicates =
            {
                "hasEconomicMotive/2", "target/2", "hasPoliticalMotive/2",
                "imposedSanctions/2", "attackYear/2", "recentNewsInYear/3", "causeOfConflict/3",
                "geolocatedInGovFacility/2", "publicCommentsRelatedToGov/2",
                "claimedResponsibility/2", "identifiedIndividualInAttack/2"
            };
    private static final String[] bgPredicates =
            {
                "prominentGroup/1", "pastTargets/2", "industry/1", "isCountry/1", "hasPrecedence/2"
            };


    GUI() {
        prepareGUI();
        utils = new Utils();
    }

    private void prepareGUI() {
        mainFrame = new JFrame("Abduction-based Reasoner");
        mainFrame.setSize(600,400);

        mainFrame.setLayout(new GridLayout(0, 1));

        status = new JLabel("", JLabel.LEFT);
        status.setAutoscrolls(true);

        dropdown = new JComboBox(
                Stream.of(techPredicates, opPredicates, bgPredicates)
                        .flatMap(Stream::of)
                        .toArray(String[]::new));
        dropdown.addItemListener(arg0 -> {
            status.setText("Selected: " + dropdown.getSelectedItem());
            evidence.setText(formatPredicate(dropdown.getSelectedItem().toString()));

        });

        evidence = new JTextField();
        evidence.setColumns(20);
        attackName = new JTextField();
        attackName.setColumns(10);

        mainFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent windowEvent){
                System.exit(0);
            }
        });
        panel1 = new JPanel();
        panel1.setLayout(new FlowLayout());

        panel2 = new JPanel();
        panel2.setLayout(new FlowLayout());

        panel3 = new JPanel();
        panel3.setLayout(new FlowLayout());

        panel4 = new JPanel();
        panel4.setLayout(new FlowLayout());

        currentEvidences = new JTextArea();

        mainFrame.add(new JLabel("Input evidence: ", JLabel.LEFT));
        panel1.add(dropdown);
        panel1.add(evidence);

        panel2.add(new JLabel("Name of attack (No spaces or '.'):", JLabel.LEFT));
        panel2.add(attackName);

        mainFrame.add(panel1);
        mainFrame.add(panel2);
        mainFrame.add(panel3);
        mainFrame.add(new JLabel("Evidence so far:", JLabel.LEFT));
        mainFrame.add(currentEvidences);
        mainFrame.add(panel4);
        mainFrame.add(status);

        mainFrame.setVisible(true);
    }

    private String formatPredicate(String s) {
        return s.split("/")[0] + '(' + ',' + ')';
    }

    private void showEventDemo(){
        JButton submitButton = new JButton("Submit");
        JButton cancelButton = new JButton("Execute");
        JButton updateButton = new JButton("Update");

        submitButton.setActionCommand("Submit");
        cancelButton.setActionCommand("Execute");
        updateButton.setActionCommand("Update");

        submitButton.addActionListener(new ButtonClickListener());
        cancelButton.addActionListener(new ButtonClickListener());
        updateButton.addActionListener(new ButtonClickListener());

        panel3.add(submitButton);
        panel3.add(cancelButton);
        panel4.add(updateButton);
        mainFrame.setVisible(true);
    }

    private class ButtonClickListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String command = e.getActionCommand();
            resetColours();

            if( command.equals( "Submit" ) )  {
                String evidenceText = evidence.getText();
                status.setText("Submitted: " + evidenceText);
                utils.addEvidence(evidenceText);
                currentEvidences.append(evidenceText + "\n");
            } else if (command.equals("Execute")){
                if (attackName.getText().length() == 0) {
                    status.setText("Please input attack name to execute query: isCulprit(<attackName>, X)");
                    highlightElement(attackName);
                } else {
                    status.setText(String.format("Executing isCulprit(%s, X)", attackName.getText()));
                    String executeResult = QueryExecutor.execute();
                    status.setText(String.format("Executing isCulprit(%s, X)\nResult:\n%s", attackName.getText(), executeResult));
//                    output = new JDialog();
//                    output.add(new JSmartTextArea("TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST"));
                    JOptionPane.showMessageDialog(mainFrame, executeResult, "Execution Result", 1);
                }
            } else {
                status.setText(String.format("Updated file: %s", utils.USER_EVIDENCE_FILENAME));
                utils.updateEvidence(currentEvidences.getText());
            }
        }
    }

    void resetColours() {
        status.setForeground(Color.darkGray);
        attackName.setBackground(Color.white);
    }

    void highlightElement(JTextComponent component) {
        status.setForeground(Color.red);
        component.setBackground(Color.pink);
    }

    public static void main(String args[]){
        GUI awt = new GUI();
        awt.showEventDemo();
    }
}