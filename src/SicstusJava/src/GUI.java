import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.*;
import java.util.List;
import java.util.stream.Stream;

@SuppressWarnings("ALL")
class GUI {
    private static final String RESULTFILENAME = "results.pl";
    private static final String NONRESULTFILENAME = "non_results.pl";

    private static final String SUBMIT = "Submit";
    private static final String UPLOAD = "Upload";
    private static final String EXECUTE = "Execute";
    private static final String UPDATE = "Update";
    private static final String EXECUTEALL = "Execute all";
    private static final String EXECUTEALLINFO = "(Get a list of predicates that can be derived by current evidences)";

    private final Utils utils;

    private JFrame mainFrame;
    private JLabel status;
    private JPanel panel1;
    private JPanel panel2;
    private JPanel panel3;
    private JPanel panel4;
    private JTextField evidence;
    private JTextField attackName;
    private JTextArea currentEvidences;
    private JasperCallable jc;
    private Map<String, Result> accumulatedResults;
    private final JFileChooser fileChooser = new JFileChooser();

    private static final String[] placeholderItem = {"Select from existing predicates"};

    private static final String[] techPredicates =
            {
                "highLevelSkill/1", "requireHighResource/1",
                "ipGeoloc/2", "attackSourceIP/2",
                "spoofedIp/1", "sysLanguage/2", "firstLanguage/2",
                "languageInCode/2", "infraRegisteredIn/2", "infraUsed/2",
                "forBlackMarketUse/1", "infectionMethod/2",
                "controlAndCommandEasilyFingerprinted/1", "similarCCServer/2",
                "ccServer/2", "domainRegisteredDetails/3", "addressType/2",
                "simlarCodeObfuscation/2", "sharedCode/2", "malwareModifiedFrom/2",
                "specificConfigInMalware/1", "malwareUsedInAttack/2",
                "usesZeroDayVulnerabilities/1", "sophisticatedMalware/1", "specificTarget/1",
                "hasKillSwitch/1", "numComputersAffected/2", "numCountriesAffected/2"
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
        utils = new Utils();
        accumulatedResults = new HashMap<>();
        prepareGUI();
        addButtonsToPanel();
    }

    private void prepareGUI() {
        mainFrame = new JFrame("Abduction-based Reasoner");
        mainFrame.setSize(800,800);

        mainFrame.setLayout(new GridLayout(0, 1));

        status = new JLabel("", JLabel.LEFT);
        status.setAutoscrolls(true);

        JComboBox dropdown = new JComboBox(
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

        JComboBox existsingAttacks = new JComboBox(new String[] {"Select predefined attacks", "us_bank_hack", "apt1", "gaussattack", "stuxnetattack", "sonyhack", "wannacryattack"});
        existsingAttacks.addItemListener(arg0 -> {
            resetColours();
            status.setText("\t\tSelected attack: " + existsingAttacks.getSelectedItem());
            attackName.setText(existsingAttacks.getSelectedItem().toString());

        });

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

        currentEvidences = new JTextArea(utils.getCurrentEvidence());
//        JScrollPane scrollPane = new JScrollPane(currentEvidences);
//        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
//        scrollPane.setPreferredSize(new Dimension(700, 200));
//        scrollPane.setVisible(true);

        mainFrame.add(new JLabel("\t\tInput evidence: ", JLabel.LEFT));
        panel1.add(dropdown);
        panel1.add(evidence);

        panel2.add(existsingAttacks);
        panel2.add(attackName);

        mainFrame.add(panel1);
        mainFrame.add(new JLabel("\t\tName of attack (No spaces or '.'):", JLabel.LEFT));

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
        JButton uploadButton = new JButton(UPLOAD);
        JButton executeButton = new JButton(EXECUTE);
        JButton executeAllButton = new JButton(EXECUTEALL);
        JButton updateButton = new JButton(UPDATE);

        submitButton.setActionCommand(SUBMIT);
        uploadButton.setActionCommand(UPLOAD);
        executeButton.setActionCommand(EXECUTE);
        executeAllButton.setActionCommand(EXECUTEALL);
        updateButton.setActionCommand(UPDATE);

        submitButton.addActionListener(new ButtonClickListener());
        uploadButton.addActionListener(new ButtonClickListener());
        executeButton.addActionListener(new ButtonClickListener());
        executeAllButton.addActionListener(new ButtonClickListener());
        updateButton.addActionListener(new ButtonClickListener());

        panel1.add(submitButton);
        panel1.add(uploadButton);
        panel2.add(executeButton);
        panel2.add(executeAllButton);
        panel2.add(new JLabel(EXECUTEALLINFO, JLabel.LEFT)); // FIXME: attach info to corrent place?
        panel4.add(updateButton);
        mainFrame.setVisible(true);
    }

    private class ButtonClickListener implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            String command = e.getActionCommand();
            resetColours();

            switch (command) {
                case SUBMIT:
                    if (checkArgs()) {
                        String evidenceText = evidence.getText();
                        status.setText("\t\tSubmitted: " + evidenceText);
                        utils.addEvidence(evidenceText);
                        currentEvidences.setText(utils.getCurrentEvidence());
                    }
                    accumulatedResults.clear();
                    break;
                case UPLOAD:
                    int returnVal = fileChooser.showOpenDialog(mainFrame);
                    if (returnVal == JFileChooser.APPROVE_OPTION) {
                        File file = fileChooser.getSelectedFile();
                        System.out.println("Opening: " + file.getName() + ".");
                        status.setText("Uploaded file: " + file.getName());
                        utils.updateRule(file);
                    }
                    currentEvidences.setText(utils.getCurrentEvidence());
                    break;
                case EXECUTE:
                    executeQuery(false);
                    break;
                case EXECUTEALL:
                    status.setText(String.format("\t\tExecuting all: %s", utils.USER_EVIDENCE_FILENAME));
                    executeQuery(true);
                    break;
                default:
                    status.setText(String.format("\t\tUpdated file: %s", utils.USER_EVIDENCE_FILENAME));
                    utils.updateEvidence(currentEvidences.getText());
                    accumulatedResults.clear();
            }
        }
    }

    private void executeQuery(boolean all) {
        if (attackName.getText().isEmpty()) {
            status.setText("\t\tPlease input attack name to executeQuery query: isCulprit(<attackName>, X)");
            highlightElement(attackName);
            return;
        } else {
            Result executeResult = null;
            if (!all && accumulatedResults.containsKey(attackName.getText())) {
                executeResult = accumulatedResults.get(attackName.getText());
            } else {
                status.setText(String.format("\t\tExecuting isCulprit(%s, X)...", attackName.getText()));
                try {
                    if (jc == null) {
                        jc = new JasperCallable();
                    }
                    jc.setName(attackName.getText());
                    jc.setAll(all);
                    executeResult = jc.call();
                    accumulatedResults.put(attackName.getText(), executeResult);
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
            }

            if (!all) {
                int option = 1;
                if (executeResult.hasAbduced()) {
                    option = 2;
                }
                JOptionPane.showConfirmDialog(mainFrame, executeResult.toString(),
                        "Execution result for " + attackName.getText(), JOptionPane.DEFAULT_OPTION, option);
            } else {
                List<String> res = readFromResultAndNonResultFiles();
                JDialog dialog = new JDialog(mainFrame);
                dialog.setLayout(new GridLayout(0, 1));
                JTextArea results = new JTextArea(res.get(0));
                results.setEditable(false);
                StringBuilder sb = new StringBuilder();
                res.remove(0);
                for (String r : res) {
                    sb.append(r + '\n');
                }
                JTextArea nonresults = new JTextArea(sb.toString());
                nonresults.setEditable(false);
                Set<String> set = new HashSet<>(res);
                JTextArea possiblerules = new JTextArea(Utils.formatMap(QueryExecutor.getPredMap(set, false)));
                possiblerules.setEditable(false);
                dialog.add(new JLabel("Results:", JLabel.LEFT));
                dialog.add(results);
                dialog.add(new JLabel("Non-results:", JLabel.LEFT));
                dialog.add(nonresults);
                dialog.add(new JLabel("Possible rules:", JLabel.LEFT));
                dialog.add(possiblerules);
                dialog.setSize(600, 800);
                dialog.setVisible(true);
//                dialog.setAlwaysOnTop(true); FIXME
                dialog.setModal(true);

            }
            mainFrame.dispose();
            prepareGUI();
            addButtonsToPanel();
        }
    }

    // elem at index 0 is combined predicates as one string read from RESULTFILENAME,
    // elem at index 1 .. n are individual predicates from NONRESULTFILENAME
    private static List<String> readFromResultAndNonResultFiles() {
        List<String> res = new ArrayList<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(RESULTFILENAME));
            final StringBuilder sb = new StringBuilder();
            br.lines().forEach(x -> sb.append(x + '\n'));
            res.add(sb.toString());
            br = new BufferedReader(new FileReader(NONRESULTFILENAME));
            br.lines().forEach(x -> res.add(x));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return res;
    }

    private boolean checkArgs() {
        if (evidence.getText().equals(placeholderItem[0]) ||
                evidence.getText().contains("<") || evidence.getText().contains(">")) {
            status.setText("\t\tSelect predicate and replace \"<arg>\" with argument");
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

    public static void main(String args[]) {
        GUI awt = new GUI();
    }
}