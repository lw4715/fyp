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
    private static final String EXECUTE = "Prove";
    private static final String UPDATE = "Update";
    private static final String EXECUTEALL = "Prove all possible predicates";
    private static final String CUSTOMEXECUTE = "Custom execute";
    private static final String EXECUTEALLINFO = "Get a list of predicates that can be derived by current evidences: ";
    private static final String EXECUTED_IS_CULPRIT = "\t\tExecuted isCulprit(%s, X)...";
    private static final String ARG_TREE = "ArgTree:";

    private final Utils utils;

    private JFrame mainFrame;
    private JLabel status;
    private JPanel panel1;
    private JPanel panel2;
    private JPanel panel3;
    private JPanel panel3b;
    private JPanel panel4;
    private JPanel panel5;
    private JTextField customQueryString;
    private JTextField evidence;
    private JTextField attackName;
    private JTextField possibleCulprits;
    private JTextArea currentEvidences;
    private JScrollPane scrollPane;
    private JasperCallable jc;

    private JFrame executeResultFrame;
    private JFrame prefFrame;

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

        evidence = new JTextField();
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
        panel3b = new JPanel();
        panel3b.setLayout(new FlowLayout());
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
        customQueryString.setColumns(50);

        panel1.add(dropdown);
        panel1.add(evidence);
        panel2.add(existsingAttacks);
        panel2.add(attackName);
        panel4.add(new JLabel("Custom query string"));
        panel4.add(customQueryString);


        mainFrame.add(new JLabel("\t\tName of attack (No spaces or '.'):", JLabel.LEFT));
        mainFrame.add(panel2);
        mainFrame.add(panel3);
        mainFrame.add(panel3b);
        mainFrame.add(panel4);

        mainFrame.add(new JLabel("\t\tInput evidence: ", JLabel.LEFT));
        mainFrame.add(panel1);

        mainFrame.add(new JLabel("\t\tInput so far:", JLabel.LEFT));
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
        JButton executeButton = new JButton(EXECUTE + " isCulprit(X,A)");
        JButton executeAllButton = new JButton(EXECUTEALL);
        JButton updateButton = new JButton(UPDATE);
        JButton customQueryExecuteButton = new JButton(CUSTOMEXECUTE);

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

        possibleCulprits = new JTextField();
        possibleCulprits.setColumns(20);

        panel1.add(submitButton);
        panel1.add(uploadButton);
        panel2.add(executeButton);
        panel3.add(new JLabel(EXECUTEALLINFO, JLabel.RIGHT));
        panel3.add(executeAllButton);
        panel3b.add(new JLabel("Possible culprits (separate by commas):"));
        panel3b.add(possibleCulprits);
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
                    String[] cs = possibleCulprits.getText().split(",");
                    List<String> csList = new ArrayList<>();
                    for (String c : cs) {
                        csList.add(c.trim());
                    }

                    status.setText(String.format("\t\tExecuted all: %s", utils.USER_EVIDENCE_FILENAME));
                    executeQueryAllWithCulprits(csList);
                    break;
                case UPDATE:
                    status.setText(String.format("\t\tUpdated file: %s", utils.USER_EVIDENCE_FILENAME));
                    utils.updateEvidence(currentEvidences.getText());
                    break;
                case CUSTOMEXECUTE:
                    String customQuery = customQueryString.getText();
                    status.setText("Executing custom query string: " + customQuery);
                    JTextArea textArea = new JTextArea();
                    String res = QueryExecutor.executeCustomQuery(customQuery);
                    if (res == null || res.equals("")) {
                        res = "False. No result for: " + customQuery;
                    }
                    textArea.setText(res);
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
                        prefFrame = new JFrame();
                        prefFrame.add(prefSP);
                        prefFrame.setSize(1000, 800);
                        prefFrame.setVisible(true);


                    } else if (command.startsWith("Choose")) {
                        // create preference rule
                        String[] s = command.split(":")[1].split(">");
                        utils.writePrefToFile(String.format("prefer(%s,%s)", s[0], s[1]));
                        currentEvidences.setText(utils.getCurrentEvidence());
                        executeResultFrame.dispose();
                        executeQuery(false);
                        prefFrame.dispose();

                    } else if (command.startsWith(ARG_TREE)) {
                        String[] s = command.split(":");
                        DerivationNode.createArgumentTreeDiagram(s[2], s[1]);
                        SVGApplication.displayFile("img/" + s[1]);
                    } else {
                        // display svg
                        SVGApplication.displayFile("img/" + command);
                    }
            }
        }
    }

    private void executeQueryAllWithCulprits(List<String> culpritsToConsider) {
        if (attackName.getText().isEmpty()) {
            status.setText("\t\tPlease input attack name to executeQuery query: isCulprit(<attackName>, X)");
            highlightElement(attackName);
            return;
        } else {
            Result executeResult = null;
            status.setText(String.format(EXECUTED_IS_CULPRIT, attackName.getText()));
            try {
                if (jc == null) {
                    jc = new JasperCallable();
                }
                jc.setName(attackName.getText());
                jc.setReload(true);
                jc.setAll(true);
                jc.setCulpritsList(culpritsToConsider);
                executeResult = jc.call();

            } catch (Exception e1) {
                e1.printStackTrace();
            }

            displayResultsAndNonResults();
        }
    }

    private void executeQuery(boolean all) {
        if (attackName.getText().isEmpty()) {
            status.setText("\t\tPlease input attack name to executeQuery query: isCulprit(<attackName>, X)");
            highlightElement(attackName);
            return;
        } else {
            Result executeResult = null;
            status.setText(String.format(EXECUTED_IS_CULPRIT, attackName.getText()));
            try {
                if (jc == null) {
                    jc = new JasperCallable();
                }
                jc.setName(attackName.getText());
                jc.setReload(true);
                jc.setAll(all);
                executeResult = jc.call();
            } catch (Exception e1) {
                e1.printStackTrace();
            }

            if (!all) {
                displayExecutionResult(executeResult);
            } else {
                displayResultsAndNonResults();

            }
        }
    }

    private void displayExecutionResult(Result executeResult) {
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

        if (executeResult.hasAbduced()) {
            p.add(new JLabel("Assumptions:"));
            JTextArea abduced = new JTextArea(executeResult.getAbducedInfo());
            abduced.setColumns(50);
            abduced.setEditable(false);
            abduced.setLineWrap(true);
            p.add(abduced);
        }

        p.add(new JLabel("Derivations:"));

        for (int i = 0; i < rs.size(); i++) {
            String r = rs.get(i);
            JTextArea textArea = new JTextArea();
            textArea.setColumns(50);
            textArea.setEditable(false);
            textArea.setText(r);
            textArea.setLineWrap(true);
            JButton viewDiagBtn = new JButton("View Diagram");
            String filename = DerivationNode.getDiagramFilename(executeResult.getAttack(), c);
            viewDiagBtn.setActionCommand(filename);
            viewDiagBtn.addActionListener(new ButtonClickListener());

            JButton viewTreeBtn = new JButton("View Argumentation Tree");
            viewTreeBtn.setActionCommand(ARG_TREE + "arg_tree_" + i + ".svg:" +  executeResult.getTree(i));
            viewTreeBtn.addActionListener(new ButtonClickListener());

            textArea.setCaretPosition(0);

            p.add(textArea);
            p.add(viewDiagBtn, Panel.LEFT_ALIGNMENT);
            p.add(viewTreeBtn, Panel.RIGHT_ALIGNMENT);
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
            }
        }
        JScrollPane scrollPane = new JScrollPane(p);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        executeResultFrame = new JFrame();
        executeResultFrame.add(scrollPane);
        executeResultFrame.setSize(1200,800);
        executeResultFrame.setVisible(true);
    }

    private void displayResultsAndNonResults() {
        List<String>[] res = readFromResultAndNonResultFiles();
        JDialog dialog = new JDialog(mainFrame);
        JPanel row1 = new JPanel();
        row1.setLayout(new FlowLayout());

        dialog.setLayout(new BoxLayout(dialog.getContentPane(), BoxLayout.Y_AXIS));
        StringJoiner sj = new StringJoiner("\n");
        for (String s : res[0]) {
            sj.add(s);
        }
        JTextArea results = new JTextArea("Results (proven):\n\n" + sj);
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
        JTextArea nonresults = new JTextArea("Other possible predicates (not proven):\n\n" + sj);
        nonresults.setCaretPosition(0);
        JScrollPane row1col2 = new JScrollPane(nonresults);
        nonresults.setEditable(false);
        nonresults.setRows(22);
        nonresults.setColumns(45);
        row1.add(row1col2);

        JTextArea possiblerules = new JTextArea("Possible rules:\n\n" + Utils.formatMap(QueryExecutor.getPredMap(res[1], false)));
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


    // elem at index 0 is combined predicates as one string read from RESULTFILENAME,
    // elem at index 1 .. n are individual predicates from NONRESULTFILENAME
    private static List<String>[] readFromResultAndNonResultFiles() {
        Set<String>[] setRes = new Set[2];
        try {
            BufferedReader br = new BufferedReader(new FileReader(RESULTFILENAME));
            Set<String> set = new HashSet<>();
            final StringBuilder sb = new StringBuilder();
            br.lines().forEach(x -> set.add(x));
            setRes[0] = set;

            Set<String> set1 = new HashSet<>();
            br = new BufferedReader(new FileReader(NONRESULTFILENAME));
            br.lines().forEach(x -> set1.add(x));
            setRes[1] = set1;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        List<String>[] res = new List[2];
        for (int i = 0; i < res.length; i++) {
            ArrayList<String> l = new ArrayList<>();
            l.addAll(setRes[i]);
            Collections.sort(l);
            res[i] = l;
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
    }
}