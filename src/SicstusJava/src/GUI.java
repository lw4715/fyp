import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.stream.Stream;

class GUI {
    private static final String SUBMIT = "Submit";
    private static final String EXECUTE = "Execute";
    private static final String UPDATE = "Update";
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
        mainFrame.setSize(800,400);

        mainFrame.setLayout(new GridLayout(0, 1));

        status = new JLabel("", JLabel.LEFT);
        status.setAutoscrolls(true);

        dropdown = new JComboBox(
                Stream.of(placeholderItem, techPredicates, opPredicates, bgPredicates)
                        .flatMap(Stream::of)
                        .toArray(String[]::new));
        dropdown.addItemListener(arg0 -> {
            resetColours();
            status.setText("\t\tSelected: " + dropdown.getSelectedItem());
            evidence.setText(formatPredicate(dropdown.getSelectedItem().toString()));

        });

        evidence = new JTextField(placeholderItem[0]);
        evidence.setColumns(35);
        attackName = new JTextField(JTextField.LEFT);
        attackName.setColumns(15);

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

        mainFrame.add(new JLabel("\t\tInput evidence: ", JLabel.LEFT));
        panel1.add(dropdown);
        panel1.add(evidence);

//        panel2.add(new JLabel("\t\tName of attack (No spaces or '.'):", JLabel.LEFT));
        panel2.add(attackName);

        mainFrame.add(panel1);
        mainFrame.add(new JLabel("\t\tName of attack (No spaces or '.'):", JLabel.LEFT));
//        mainFrame.add(attackName);
        mainFrame.add(panel2);
        mainFrame.add(panel3);
        mainFrame.add(new JLabel("\t\tEvidence so far:", JLabel.LEFT));
        mainFrame.add(currentEvidences);
        mainFrame.add(panel4);
        mainFrame.add(status);

        mainFrame.setVisible(true);
    }

    private String formatPredicate(String s) {
        String[] split = s.split("/");
        StringBuilder sb = new StringBuilder();
        sb.append("<arg>");
        for (int i = 1; i < Integer.parseInt(split[1]); i++) {
            sb.append(", <arg>");
        }
        return split[0] + '(' + sb + ')';
    }

    private void addButtonsToPanel(){
        JButton submitButton = new JButton(SUBMIT);
        JButton cancelButton = new JButton(EXECUTE);
        JButton updateButton = new JButton(UPDATE);

        submitButton.setActionCommand(SUBMIT);
        cancelButton.setActionCommand(EXECUTE);
        updateButton.setActionCommand(UPDATE);

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

            if( command.equals(SUBMIT))  {
                if (checkArgs()) {
                    String evidenceText = evidence.getText();
                    status.setText("\t\tSubmitted: " + evidenceText);
                    utils.addEvidence(evidenceText);
                    currentEvidences.append(evidenceText + "\n");
                }
            } else if (command.equals(EXECUTE)){
                if (attackName.getText().isEmpty()) {
                    status.setText("\t\tPlease input attack name to execute query: isCulprit(<attackName>, X)");
                    highlightElement(attackName);
                } else {
                    status.setText(String.format("\t\tExecuting isCulprit(%s, X)...", attackName.getText()));
                    String executeResult = QueryExecutor.execute(attackName.getText());
                    JOptionPane.showMessageDialog(mainFrame, executeResult, "Execution Result", 1);
                }
            } else {
                status.setText(String.format("\t\tUpdated file: %s", utils.USER_EVIDENCE_FILENAME));
                utils.updateEvidence(currentEvidences.getText());
            }
        }
    }

    private boolean checkArgs() {
        if (evidence.getText().contains("<") || evidence.getText().contains(">")) {
            status.setText("\t\tReplace \"<arg>\" with argument");
            highlightElement(evidence);
            return false;
        }
        return true;
    }

    void resetColours() {
        status.setForeground(Color.darkGray);
        evidence.setBackground(Color.white);
        attackName.setBackground(Color.white);
    }

    void highlightElement(JTextComponent component) {
        status.setForeground(Color.red);
        component.setBackground(Color.pink);
    }

    public static void main(String args[]){
        GUI awt = new GUI();
        awt.addButtonsToPanel();
    }
}