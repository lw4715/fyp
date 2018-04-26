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
                "highLevelSkill(<attack_id>)", "requireHighResource(<attack_id>)",
                "attackSourceIP(<ip_id>, <attack_id>)","ipGeoloc(<country>,<ip_id>)",
                "spoofedIp(<ip_id>)", "sysLanguage(<language>,<attack_id>)", "firstLanguage(<language>,<country>)",
                "languageInCode(<language>,<attack_id>)", "infraUsed(<infra_id>, <attack_id>)",
                "infraRegisteredIn(<country>,<infra_id>)", "forBlackMarketUse(<malware_id>)",
                "infectionMethod(<infection_method>, <malware_id>)",
                "controlAndCommandEasilyFingerprinted(<malware_id>)", "ccServer(<server_id>,<malware_id>)",
                "similarCCServer(<malware_id>,<malware_id>)",
                "domainRegisteredDetails(<server_id>,<name>,<address>)", "addressType(<address>,<type>)",
                "simlarCodeObfuscation(<malware_id>,<malware_id>)", "sharedCode(<malware_id>,<malware_id>)",
                "malwareModifiedFrom(<malware_id>,<malware_id>)",
                "specificConfigInMalware(<malware_id>)", "malwareUsedInAttack(<malware_id>,<attack_id>)",
                "usesZeroDayVulnerabilities(<malware_id>)", "sophisticatedMalware(<malware_id>)", "specificTarget(<attack_id>)",
                "hasKillSwitch(<malware_id>)",
//                    "numComputersAffected", "numCountriesAffected/2"
        };
    private static final String[] opPredicates =
            {
                "hasEconomicMotive/2", "target/2", "hasPoliticalMotive/2",
                "imposedSanctions/3", "attackPeriod/2", "news/3", "causeOfConflict/3",
                "geolocatedInGovFacility/2", "publicCommentsRelatedToGov/2",
                "claimedResponsibility/2", "identifiedIndividualInAttack/2"
            };
    private static final String[] bgPredicates =
            {
                "prominentGroup/1", "pastTargets/2", "industry/1", "country/1", "hasPrecedence/2"
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
            evidence.setText(dropdown.getSelectedItem().toString());

        });

        evidence = new JTextField(placeholderItem[0]);
        evidence.setColumns(35);
        attackName = new JTextField(JTextField.LEFT);
        attackName.setColumns(15);

        JComboBox existsingAttacks = new JComboBox(new String[] {"Select predefined attacks", "usbankhack", "apt1", "gaussattack", "stuxnetattack", "sonyhack", "wannacryattack"});
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

//    private String formatPredicate(String s) {
//        String[] split = s.split("/");
//        StringBuilder sb = new StringBuilder();
//        sb.append("<arg>");
//        for (int i = 1; i < Integer.parseInt(split[1]); i++) {
//            sb.append(", <arg>");
//        }
//        return split[0] + '(' + sb + ')';
//    }

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
                    status.setText(String.format("\t\tExecuted all: %s", utils.USER_EVIDENCE_FILENAME));
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
                status.setText(String.format("\t\tExecuted isCulprit(%s, X)...", attackName.getText()));
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
                Set<String>[] res = readFromResultAndNonResultFiles();
                JDialog dialog = new JDialog(mainFrame);
                dialog.setLayout(new GridLayout(1, 3));
                StringJoiner sj = new StringJoiner("\n");
                for (String s : res[0]) {
                    sj.add(s);
                }
                JTextArea results = new JTextArea("Results:\n" + sj);

                results.setEditable(false);
                sj = new StringJoiner("\n");
                for (String s : res[1]) {
                    sj.add(s);
                }
                JTextArea nonresults = new JTextArea("Other possible predicates:\n" + sj);

                nonresults.setEditable(false);
                JTextArea possiblerules = new JTextArea("Possible rules:\n" + Utils.formatMap(QueryExecutor.getPredMap(res[1], false)));
                possiblerules.setEditable(false);
                dialog.add(results);
                dialog.add(nonresults);
                dialog.add(possiblerules);
                dialog.setSize(1600, 1000);
                dialog.setVisible(true);
//                dialog.setAlwaysOnTop(true); FIXME
                dialog.setModal(true);

            }
        }
    }

    // elem at index 0 is combined predicates as one string read from RESULTFILENAME,
    // elem at index 1 .. n are individual predicates from NONRESULTFILENAME
    private static Set<String>[] readFromResultAndNonResultFiles() {
        Set<String>[] res = new Set[2];
        try {
            BufferedReader br = new BufferedReader(new FileReader(RESULTFILENAME));
            Set<String> set = new HashSet<>();
            final StringBuilder sb = new StringBuilder();
            br.lines().forEach(x -> set.add(x));
            res[0] = set;

            Set<String> set1 = new HashSet<>();
            br = new BufferedReader(new FileReader(NONRESULTFILENAME));
            br.lines().forEach(x -> set1.add(x));
            res[1] = set1;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return res;
    }

    private boolean checkArgs() {
        if (evidence.getText().equals(placeholderItem[0]) ||
                evidence.getText().contains("<") || evidence.getText().contains(">")) {
            status.setText("\t\tSelect predicate and replace \"<argument>\" with argument");
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