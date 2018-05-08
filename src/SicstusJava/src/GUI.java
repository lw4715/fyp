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

@SuppressWarnings("ALL")
class GUI {
    private static final String RESULTFILENAME = "results.pl";
    private static final String NONRESULTFILENAME = "non_results.pl";

    private static final String SUBMIT = "Submit";
    private static final String UPLOAD = "Upload";
    private static final String EXECUTE = "Execute";
    private static final String UPDATE = "Update";
    private static final String EXECUTEALL = "Execute all";
    private static final String CUSTOMEXECUTE = "Custom execute";
    private static final String EXECUTEALLINFO = "(Get a list of predicates that can be derived by current evidences)";

    private final Utils utils;

    private JFrame mainFrame;
    private JLabel status;
    private JPanel panel1;
    private JPanel panel2;
    private JPanel panel3;
    private JPanel panel4;
    private JPanel panel5;
    private JTextField customQueryString;
    private JTextField evidence;
    private JTextField attackName;
    private JTextArea currentEvidences;
    private JScrollPane scrollPane;
    private JasperCallable jc;
    private Map<String, Result> accumulatedResults;
    private final JFileChooser fileChooser = new JFileChooser();

    private static final String placeholderItem = "Select from existing predicates";

    private static final String[] predicates = {"industry(<T>)","targetCountry(<X>,<Att>)",
            "fileChara(<Filename>,<MD5>,<Size>,<CompileTime>,<Desc>,<Filetype>,<C1>)","poorRelation(<C>,<T>)",
            "noPriorHistory(<X>)","infraUsed(<Infra>,<Att>)","hasResources(<X>)","majorityIpOrigin(<X>,<Att>)",
            "stolenValidSignedCertificates(<Att>)","cybersuperpower(<X>)","espionage>,<doxing>)",
            "attackPeriod(<Att>,<[Year>,<Month]>)","governmentLinked(<P>,<C>)",
            "domainRegisteredDetails(<Server>,<Name>,<Addr>)","ipResolution(<S>,<IP>,<D>)",
            "infectionMethod(<usb>,<M>)","attackOrigin(<X>,<Att>)","highLevelSkill(<Att>)",
            "usesZeroDayVulnerabilities(<M>)","hasPoliticalMotive(<C>,<T>,<Date2>)",
            "malwareUsedInAttack(<M>,<Att>)","news(<News>,<T>,<Date2>)","prominentGroup(<X>)",
            "attackPossibleOrigin(<X>,<Att>)","notForBlackMarket        Use(<M>)","similarCCServer(<M1>,<M2>)",
            "publicCommentsRelatedToGov(<P>,<C>)","zeroday>,<customMalware>)","gci_tier(<X>,<leading>)",
            "torIP(<IP>)","malwareLinkedTo(<M2>,<X>)","sysLanguage(<L>,<Att>)","clientSideExploits>)",
            "eternalBlue>)","spoofedIP(<IP>)","ipGeoloc(<X>,<IP>)","addressType(<Addr>,<Type>)",
            "sophisticatedMalware(<M>)","identifiedIndividualInAttack(<P>,<Att>)",
            "goodRelation(<X>,<Y>)","industry(<Ind>,<X>)","cyberespionage>)",
            "languageInCode(<L>,<Att>)","groupOrigin(<Group>,<C>)","hasCapability(<X>,<Att>)",
            "isInfrastructure(<Ind>)","infraRegisteredIn(<X>,<Infra>)","informationRich(<Ind>)",
            "hasResources(<X>)","fileCharaMalware(<C2>,<M2>)","claimedResponsibility(<X>,<Att>)",
            "addrInCountry(<Addr>,<X>)","similarFileChara(<C1>,<C2>)","dateApplicable(<Date1>,<Date2>)",
            "attackSourceIP(<IP>,<M>)","hijackCorporateClouds(<Att>)","highVolumeAttack(<Att>)",
            "imposedSanctions(<T>,<C>,<Date>)","causeOfConflict(<X>,<T>,<News>)","ccServer(<S>,<M>)",
            "specificConfigInMalware(<M>)","cyberespionage>,<undergroundBusiness>)",
            "specificTarget(<Att>)","simlarCodeObfuscation(<M1>,<M2>)","requireHighResource(<Att>)",
            "target(<X>,<Att>)","hasMotive(<X>,<Att>)","similar(<M1>,<M2>)","hasEconomicMotive(<C>,<T>)",
            "longDurationAttack(<Att>)","sharedCode(<M1>,<M2>)","commandAndControlEasilyFingerprinted(<M>)",
            "highSecurity(<T>)","firstLanguage(<L>,<X>)","geolocatedInGovFacility(<P>,<C>)","country(<X>)",
            "malwareModifiedFrom(<M1>,<M2>)","gci_tier(<X>,<initiating>)","gci_tier(<X>,<maturing>)",
            "isCulprit(<Group>,<Att>)"};

//    private static final String[] techPredicates =
//            {
//                "highLevelSkill(<attack_id>)", "requireHighResource(<attack_id>)",
//                "attackSourceIP(<ip_id>, <attack_id>)","ipGeoloc(<country>,<ip_id>)",
//                "spoofedIp(<ip_id>)", "sysLanguage(<language>,<attack_id>)", "firstLanguage(<language>,<country>)",
//                "languageInCode(<language>,<attack_id>)", "infraUsed(<infra_id>, <attack_id>)",
//                "infraRegisteredIn(<country>,<infra_id>)", "forBlackMarketUse(<malware_id>)",
//                "infectionMethod(<infection_method>, <malware_id>)",
//                "controlAndCommandEasilyFingerprinted(<malware_id>)", "ccServer(<server_id>,<malware_id>)",
//                "similarCCServer(<malware_id>,<malware_id>)",
//                "domainRegisteredDetails(<server_id>,<name>,<address>)", "addressType(<address>,<type>)",
//                "simlarCodeObfuscation(<malware_id>,<malware_id>)", "sharedCode(<malware_id>,<malware_id>)",
//                "malwareModifiedFrom(<malware_id>,<malware_id>)",
//                "specificConfigInMalware(<malware_id>)", "malwareUsedInAttack(<malware_id>,<attack_id>)",
//                "usesZeroDayVulnerabilities(<malware_id>)", "sophisticatedMalware(<malware_id>)", "specificTarget(<attack_id>)",
//                "hasKillSwitch(<malware_id>)",
////                    "numComputersAffected", "numCountriesAffected/2"
//        };
//    private static final String[] opPredicates =
//            {
//                "hasEconomicMotive/2", "target/2", "hasPoliticalMotive/2",
//                "imposedSanctions/3", "attackPeriod/2", "news/3", "causeOfConflict/3",
//                "geolocatedInGovFacility/2", "publicCommentsRelatedToGov/2",
//                "claimedResponsibility/2", "identifiedIndividualInAttack/2"
//            };
//    private static final String[] bgPredicates =
//            {
//                "prominentGroup/1", "pastTargets/2", "industry/1", "country/1", "hasPrecedence/2"
//            };


    GUI() {
        utils = new Utils();
        accumulatedResults = new HashMap<>();
        prepareGUI();
        addButtonsToPanel();
    }

    private void prepareGUI() {
        mainFrame = new JFrame("Abduction-based Reasoner");

        mainFrame.setLayout(new BoxLayout(mainFrame.getContentPane(), BoxLayout.Y_AXIS));

        status = new JLabel("", JLabel.LEFT);
        status.setAutoscrolls(true);

        ArrayList predList = new ArrayList();
        predList.add(placeholderItem);
        Collections.addAll(predList, predicates);
        JComboBox dropdown = new JComboBox(predList.toArray());
        dropdown.addItemListener(arg0 -> {
            resetColours();
            status.setText("\t\tSelected: " + dropdown.getSelectedItem());
            evidence.setText(dropdown.getSelectedItem().toString());

        });
        dropdown.setSize(70,0);

        evidence = new JTextField(placeholderItem);
        evidence.setColumns(35);
        attackName = new JTextField(JTextField.LEFT);
        attackName.setColumns(15);

        JComboBox existsingAttacks = new JComboBox(new String[] {"Select predefined attacks",
                "usbankhack", "apt1", "gaussattack", "stuxnetattack", "sonyhack", "wannacryattack",
                "example0", "example1", "example2", "example2b", "example3", "example4"});
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
        panel5 = new JPanel();
        panel5.setLayout(new FlowLayout());

        currentEvidences = new JTextArea(utils.getCurrentEvidence());
        currentEvidences.setColumns(60);
        currentEvidences.setRows(10);
        scrollPane = new JScrollPane(currentEvidences);
        scrollPane.setSize(0,300);

        customQueryString = new JTextField("prove([<list of predicates to prove>], D)");
        customQueryString.setColumns(60);

        panel1.add(dropdown);
        panel1.add(evidence);
        panel2.add(existsingAttacks);
        panel2.add(attackName);
        panel4.add(new JLabel("Custom query string"));
        panel4.add(customQueryString);


        mainFrame.add(new JLabel("\t\tName of attack (No spaces or '.'):", JLabel.LEFT));
        mainFrame.add(panel2);
        mainFrame.add(panel3);
        mainFrame.add(panel4);

        mainFrame.add(new JLabel("\t\tInput evidence: ", JLabel.LEFT));
        mainFrame.add(panel1);

        mainFrame.add(new JLabel("\t\tCustom input so far:", JLabel.LEFT));
        mainFrame.add(scrollPane);

        mainFrame.add(panel5);
        mainFrame.add(status);

        mainFrame.setSize(1000,750);
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
        JButton customQueryExecuteButton = new JButton(EXECUTE);

        submitButton.setActionCommand(SUBMIT);
        uploadButton.setActionCommand(UPLOAD);
        executeButton.setActionCommand(EXECUTE);
        executeAllButton.setActionCommand(EXECUTEALL);
        updateButton.setActionCommand(UPDATE);
        customQueryExecuteButton.setActionCommand(CUSTOMEXECUTE);

        submitButton.addActionListener(new ButtonClickListener());
        uploadButton.addActionListener(new ButtonClickListener());
        executeButton.addActionListener(new ButtonClickListener());
        executeAllButton.addActionListener(new ButtonClickListener());
        updateButton.addActionListener(new ButtonClickListener());
        customQueryExecuteButton.addActionListener(new ButtonClickListener());

        panel1.add(submitButton);
        panel1.add(uploadButton);
        panel2.add(executeButton);
        panel3.add(executeAllButton);
        panel3.add(new JLabel(EXECUTEALLINFO, JLabel.RIGHT));
        panel4.add(customQueryExecuteButton);
        panel5.add(updateButton);
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
                    executeQuery(false, false);
                    break;
                case EXECUTEALL:
                    status.setText(String.format("\t\tExecuted all: %s", utils.USER_EVIDENCE_FILENAME));
                    executeQuery(true, false);
                    break;
                case UPDATE:
                    status.setText(String.format("\t\tUpdated file: %s", utils.USER_EVIDENCE_FILENAME));
                    utils.updateEvidence(currentEvidences.getText());
                    accumulatedResults.clear();
                    break;
                case CUSTOMEXECUTE:
                    String customQuery = customQueryString.getText();
                    status.setText("Executing custom query string: " + customQuery);
                    JTextArea textArea = new JTextArea();
                    textArea.setText(QueryExecutor.executeCustomQuery(customQuery));
                    textArea.setEditable(false);
                    textArea.setRows(40);
                    textArea.setCaretPosition(0);
                    textArea.setLineWrap(true);

                    JPanel p = new JPanel();
                    p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
                    p.add(new JLabel("Custom query result for " + customQuery, JLabel.RIGHT));
                    p.add(textArea);

                    JScrollPane sp = new JScrollPane(p);
                    sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

                    JFrame f = new JFrame();
                    f.add(sp);
                    f.setSize(1200,1000);
                    f.setVisible(true);
                    break;
                default:
                    // add pref
                    if (command.startsWith("[")) {
                        String[] s = command.split("\\*");
                        String negDer = s[0];
                        String[] posDers = s[1].split("#");

                        JTextArea ntf = new JTextArea(negDer);
                        ntf.setColumns(30);
                        ntf.setLineWrap(true);


                        JPanel prefP = new JPanel();
                        prefP.setLayout(new BoxLayout(prefP, BoxLayout.Y_AXIS));
                        prefP.add(new JLabel("Negative derivation:"));
                        prefP.add(ntf);
                        prefP.add(new JLabel("Positive derivations:"));
                        for (String posDer : posDers) {
                            List<String> conflictingRules = QueryExecutor.getConflictingRule(posDer, negDer);
                            JButton choosePos = new JButton("Prefer " + conflictingRules.get(0));
                            JButton chooseNeg = new JButton("Prefer " + conflictingRules.get(1));
                            choosePos.setActionCommand("Choose0:" + conflictingRules.get(0) + ">" + conflictingRules.get(1));
                            chooseNeg.setActionCommand("Choose1:" + conflictingRules.get(1) + ">" + conflictingRules.get(0));
                            choosePos.addActionListener(new ButtonClickListener());
                            chooseNeg.addActionListener(new ButtonClickListener());


                            JTextArea ptf = new JTextArea(posDer);
                            ptf.setColumns(30);
                            ptf.setLineWrap(true);

                            prefP.add(ptf);
                            prefP.add(choosePos);
                            prefP.add(chooseNeg);
                        }

                        JScrollPane prefSP = new JScrollPane(prefP);
                        JFrame prefFrame = new JFrame();
                        prefFrame.add(prefSP);
                        prefFrame.setSize(1000, 800);
                        prefFrame.setVisible(true);

                    } else if (command.startsWith("Choose")) {
                        // create preference rule
                        String[] s = command.split(":")[1].split(">");
                        utils.writePrefToFile(String.format("prefer(%s,%s)", s[0], s[1]));
                        currentEvidences.setText(utils.getCurrentEvidence());
                        executeQuery(false, true);
                    } else {
                        // display svg
                        SVGApplication.displayFile("img/" + command);
                    }
            }
        }
    }

    private void executeQuery(boolean all, boolean reload) {
        if (attackName.getText().isEmpty()) {
            status.setText("\t\tPlease input attack name to executeQuery query: isCulprit(<attackName>, X)");
            highlightElement(attackName);
            return;
        } else {
            if (reload) {
                accumulatedResults.clear();
            }
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
                    jc.setReload(reload);
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

                JPanel p = new JPanel();
                p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
                List<String> rs = executeResult.resultStrings();
                int c = 0;

                p.add(new JLabel("Summary:"));
                JTextArea ta = new JTextArea();
                ta.setColumns(50);
                ta.setEditable(false);
                ta.setLineWrap(true);
                ta.setText(executeResult.getCulpritsSummary());
                ta.setCaretPosition(0);
                p.add(ta);
                p.add(new JLabel("Derivations:"));

                for (int i = 0; i < rs.size(); i++) {
                    String r = rs.get(i);
                    JTextArea textArea = new JTextArea();
                    textArea.setColumns(50);
                    textArea.setEditable(false);
                    textArea.setText(r);
                    textArea.setLineWrap(true);
                    JButton btn = new JButton("View diagram");
                    String filename = DerivationNode.getDiagramFilename(executeResult.getAttack(), c);
                    btn.setActionCommand(filename);
                    btn.addActionListener(new ButtonClickListener());
                    textArea.setCaretPosition(0);
                    p.add(textArea);
                    p.add(btn, Panel.LEFT_ALIGNMENT);
                    c++;
                }

                if (executeResult.hasNegDerivations()) {
                    p.add(new JLabel("Negative Derivations: " + executeResult.getNumNegDerivations()));
                }

                for (String culprit : executeResult.getCulprits()) {
                    for (String nd : executeResult.negDerivationFor(culprit)) {
                        p.add(new JLabel(String.format("neg(isCulprit(%s,%s))", culprit, attackName.getText())));
                        JTextArea textArea = new JTextArea();
                        textArea.setEditable(false);
                        textArea.setText(nd);
                        textArea.setLineWrap(true);
                        textArea.setCaretPosition(0);
                        p.add(textArea);
                        JButton addPrefBtn = new JButton("Add rule preference");
                        addPrefBtn.setActionCommand(nd + "*" + executeResult.getDerivationsForCulprit(culprit));
                        addPrefBtn.addActionListener(new ButtonClickListener());
                        p.add(addPrefBtn);
//                        String filename = DerivationNode.getDiagramFilename(executeResult.getAttack(), c);
                    }
                }
                JScrollPane scrollPane = new JScrollPane(p);
                scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
                JFrame f = new JFrame();
                f.add(scrollPane);
                f.setSize(1200,800);
                f.setVisible(true);

            } else {
                Set<String>[] res = readFromResultAndNonResultFiles();
                JDialog dialog = new JDialog(mainFrame);
                JPanel row1 = new JPanel();
                row1.setLayout(new FlowLayout());

                dialog.setLayout(new BoxLayout(dialog.getContentPane(), BoxLayout.Y_AXIS));
                StringJoiner sj = new StringJoiner("\n");
                for (String s : res[0]) {
                    sj.add(s);
                }
                JTextArea results = new JTextArea("Results:\n" + sj);
                results.setEditable(false);
                results.setRows(22);
                results.setColumns(45);
                results.setCaretPosition(0);
                JScrollPane row1col1 = new JScrollPane(results);
                row1.add(row1col1);

                sj = new StringJoiner("\n");
                for (String s : res[1]) {
                    sj.add(s);
                }
                JTextArea nonresults = new JTextArea("Other possible predicates:\n" + sj);
                nonresults.setCaretPosition(0);
                JScrollPane row1col2 = new JScrollPane(nonresults);
                nonresults.setEditable(false);
                nonresults.setRows(22);
                nonresults.setColumns(45);
                row1.add(row1col2);

                JTextArea possiblerules = new JTextArea("Possible rules:\n" + Utils.formatMap(QueryExecutor.getPredMap(res[1], false)));
                possiblerules.setEditable(false);
                possiblerules.setColumns(90);
                possiblerules.setCaretPosition(0);
                JScrollPane row2 = new JScrollPane(possiblerules);

                dialog.add(row1);
                dialog.add(row2);
                dialog.setSize(1200, 1000);
                dialog.setVisible(true);
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
        if (evidence.getText().equals(placeholderItem) ||
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
//        String la = "[r_op_notTargetted(example2b), case_example2b_f2b(), case_example2b_f2(), r_t_highSkill0(example2b), r_t_highResource0(example2b), r_op_hasCapability1(yourCountry, example2b), case_example2b_f8(), r_str_motiveAndCapability(yourCountry, example2b)]|[r_op_notTargetted(example2b), case_example2b_f2(), case_example2b_f2b(), r_t_highSkill0(example2b), r_t_highResource0(example2b), r_op_hasCapability1(yourCountry, example2b), case_example2b_f8(), r_str_motiveAndCapability(yourCountry, example2b)]|[r_op_notTargetted(example2b), case_example2b_f2b(), case_example2b_f2(), p4a_t(), case_example2b_f10(), case_example2b_f9(), case_example2b_f1a(), r_t_srcIP1(yourCountry, example2b), r_t_attackOrigin(yourCountry, example2b), case_example2b_f8(), bg1(), r_str_motiveAndLocation(yourCountry, example2b)]|[r_op_notTargetted(example2b), case_example2b_f2(), case_example2b_f2b(), p4a_t(), case_example2b_f10(), case_example2b_f9(), case_example2b_f1a(), r_t_srcIP1(yourCountry, example2b), r_t_attackOrigin(yourCountry, example2b), case_example2b_f8(), bg1(), r_str_motiveAndLocation(yourCountry, example2b)]|[r_op_notTargetted(example2b), case_example2b_f2b(), case_example2b_f2(), p4a_t(), case_example2b_f10(), case_example2b_f9(), case_example2b_f1a(), r_t_srcIP1(yourCountry, example2b), r_t_attackOrigin(yourCountry, example2b), bg1(), r_str_loc(yourCountry, example2b)]|[r_op_notTargetted(example2b), case_example2b_f2(), case_example2b_f2b(), p4a_t(), case_example2b_f10(), case_example2b_f9(), case_example2b_f1a(), r_t_srcIP1(yourCountry, example2b), r_t_attackOrigin(yourCountry, example2b), bg1(), r_str_loc(yourCountry, example2b)]|[r_op_notTargetted(example2b), case_example2b_f2b(), case_example2b_f2(), ass(notForBlackMarketUse(example2b_m2)), ass(notForBlackMarketUse(example2b_m1)), case_example2b_f5(), case_example2b_f4(), r_t_similar1(example2b_m1, example2b_m2), case_example2b_f3(), r_str_linkedMalware(yourCountry, example2b)]|[r_op_notTargetted(example2b), case_example2b_f2(), case_example2b_f2b(), ass(notForBlackMarketUse(example2b_m2)), ass(notForBlackMarketUse(example2b_m1)), case_example2b_f5(), case_example2b_f4(), r_t_similar1(example2b_m1, example2b_m2), case_example2b_f3(), r_str_linkedMalware(yourCountry, example2b)]";
//        System.out.println(la.split("|"));
//        System.out.println(la.split("|").length);
//        System.out.println(la.split("|")[0]);
    }
}