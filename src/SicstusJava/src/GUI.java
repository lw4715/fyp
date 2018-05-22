import javafx.util.Pair;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SuppressWarnings("ALL")
class GUI {
    private static final String RESULTFILENAME = "results.pl";
    private static final String NONRESULTFILENAME = "non_results.pl";

    // commands/command prefixes
    private static final String SUBMIT = "Submit";
    private static final String UPLOAD = "Upload";
    private static final String EXECUTE = "Prove";
    private static final String UPDATE = "Update";
    private static final String EXECUTEALL = "Prove all possible predicates";
    private static final String CUSTOMEXECUTE = "Custom execute";
    private static final String EXECUTEALLINFO = "Get a list of predicates that can be derived by current evidences: ";
    private static final String EXECUTED_IS_CULPRIT = "\t\tExecuted isCulprit(%s, X)...";
    private static final String ARG_TREE = "ArgTree:";
    private static final String UPLOAD_LOG = "Upload and process snort log";
    private static final String OPEN_TOOL_INTEGRATION = "Open tool integration";
    private static final String ADD_PREF = "AddPref_";
    private static final String SEPARATOR = "#";
    private static final String PREF_TYPE = "PrefType_";
    private static final String VIEW_PREF = "View Pref";
    private static final String USER_INSERT_RULE = "USER INSERT RULE";
    private static final String USER_INSERT_RULE_START = "USER INSERT RULE START";
    private static final String DISPLAY_RESULTS = "DISPLAY RESULTS";
    private static final String DISPLAY_RULE_SEARCH = "DISPLAY RULE SEARCH";
    private static final String DISPLAY_RULES = "Search for a rule";

    private final Utils utils;

    private QueryExecutor qe;
    private JFrame mainFrame;
    private JLabel status;
    private JPanel panel2;
    private JPanel panel3;
    private JPanel panel3b;
    private JPanel panel4;
    private JPanel panel5b;
    private JPanel panel6;
    private JTextField customQueryString;
    private JTextField evidence;
    private JTextField attackName;
    private JTextField possibleCulprits;
    private JTextField logAttackname;
    private JTextArea currentEvidences;
    private JScrollPane scrollPane;
    private JasperCallable jc;

    private JFrame executeResultFrame;
    private JFrame prefFrame;
    private JFrame toolIntegrationFrame;
    private JLabel toolIntegrationStatus;
    private JFrame insertNewRuleFrame;
    private JTextField userNewRule;
    private JPanel userRuleConflicts;
    private JTextArea userRuleConflictStatus;
    private JTextArea logStatus;
    private JFrame displayRulesFrame;
    private JTextField displayRulesTextField;


    private List<Pair<String, String>> strRulePrefs;
    private Result reloadResult;

    private final JFileChooser fileChooser = new JFileChooser();

    private static final String placeholderItem = "Select from existing predicates";

    private static final String[] bgPredicates = {"firstLanguage(L,X)",
            "country(Y)", "gci_tier(X,leading)", "cybersuperpower(X)",
            "industry(T)", "poorRelation(C,T)", "goodRelation(C,T)", "industry(Ind,T)",
            "normalIndustry(Ind)", "politicalIndustry(Ind)", "prominentGroup()", "country()",
            "groupOrigin()", "malwareLinkedTo()", "gci_tier()"};

    private static final String[] evidencePredicates = {"hijackCorporateClouds(Att)",
            "malwareUsedInAttack(M,Att)", "notForBlackMarketUse(M)", "stolenValidSignedCertificates(Att)",
            "highSecurity(T)", "target(T,Att)", "highVolumeAttack(Att)", "longDurationAttack(Att)",
            "majorityIpOrigin(X,Att)", "attackPeriod(Att,D1)", "targetServerIP(TargetServerIP,Att)",
            "sysLanguage(L,Att)", "languageInCode(L,Att)", "infraUsed(Infra,Att)",
            "infraRegisteredIn(X,Infra)", "ccServer(S,M)", "domainRegisteredDetails(S,_,Addr)",
            "addrInCountry(Addr,X)", "infectionMethod(usb,M)", "commandAndControlEasilyFingerprinted(M)",
            "simlarCodeObfuscation(M1,M2)", "sharedCode(M1,M2)", "malwareModifiedFrom(M1,M2)",
            "fileCharaMalware(C2,M2)", "specificConfigInMalware(M)", "usesZeroDayVulnerabilities(M)",
            "fileChara(Filename,_,_,_,_,_,C2)", "targetCountry(T1,Att)", "target(T,Att)",
            "hasEconomicMotive(C,T)", "targetCountry(T,Att)", "attackPeriod(Att,Date1)",
            "hasPoliticalMotive(C,T,Date2)", "imposedSanctions(T,C,Date)", "news(News,T,Date2)",
            "causeOfConflict(X,T,News)", "claimedResponsibility(X,Att)", "noPriorHistory(X)",
            "geolocatedInGovFacility(P,C)", "publicCommentsRelatedToGov(P,C)", "attackOrigin()",
            "identifiedIndividualInAttack()", "malwareUsedInAttack()", "target()", "targetCountry()"};

    private static final String[] predicates = {"industry(<T>)","targetCountry(<X>,<Att>)",
            "fileChara(<Filename>,<MD5>,<Size>,<CompileTime>,<Desc>,<Filetype>,<C1>)","poorRelation(<C>,<T>)",
            "noPriorHistory(<X>)","infraUsed(<Infra>,<Att>)","hasResources(<X>)","majorityIpOrigin(<X>,<Att>)",
            "stolenValidSignedCertificates(<Att>)","cybersuperpower(<X>)",
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
            "attackSourceIP(<IP>,<Att>)","hijackCorporateClouds(<Att>)","highVolumeAttack(<Att>)",
            "imposedSanctions(<T>,<C>,<Date>)","causeOfConflict(<X>,<T>,<News>)","ccServer(<S>,<M>)",
            "specificConfigInMalware(<M>)","cyberespionage>,<undergroundBusiness>)",
            "specificTarget(<Att>)","simlarCodeObfuscation(<M1>,<M2>)","requireHighResource(<Att>)",
            "target(<X>,<Att>)","hasMotive(<X>,<Att>)","similar(<M1>,<M2>)","hasEconomicMotive(<C>,<T>)",
            "longDurationAttack(<Att>)","sharedCode(<M1>,<M2>)","commandAndControlEasilyFingerprinted(<M>)",
            "highSecurity(<T>)","firstLanguage(<L>,<X>)","geolocatedInGovFacility(<P>,<C>)","country(<X>)",
            "malwareModifiedFrom(<M1>,<M2>)","gci_tier(<X>,<initiating>)","gci_tier(<X>,<maturing>)",
            "isCulprit(<Group>,<Att>)"};

    GUI() {
        qe = QueryExecutor.getInstance();
        utils = new Utils();
        prepareGUI();
        addButtonsToPanel();
    }

    private void prepareGUI() {
        mainFrame = new JFrame("Argumentation-Based Reasoner (ABR)");

//        mainFrame.setLayout(new BoxLayout(mainFrame.getContentPane(), BoxLayout.Y_AXIS));

        status = new JLabel("", JLabel.LEFT);

        strRulePrefs = new ArrayList();
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
                "autogeoloc_ex", "tor_ex", "squid_ex",
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
        panel2 = defaultJPanel();
        panel3 = defaultJPanel();
        panel3b = defaultJPanel();
        panel4 = defaultJPanel();
        JPanel panel5a = defaultJPanel();
        panel5b = defaultJPanel();
        panel6 = defaultJPanel();

        currentEvidences = new JTextArea(utils.getCurrentEvidence());
        currentEvidences.setColumns(60);
        currentEvidences.setRows(10);
        scrollPane = new JScrollPane(currentEvidences);
        scrollPane.setSize(0,300);

        customQueryString = new JTextField("prove([<list of predicates to prove>], D)");
        customQueryString.setColumns(50);

        panel2.add(existsingAttacks);
        panel2.add(attackName);
        panel4.add(new JLabel("Custom query string"));
        panel4.add(customQueryString);
        panel5a.add(dropdown);
        panel5a.add(evidence);

        JButton toolIntegrationBtn = new JButton("Tool integration");
        toolIntegrationBtn.setActionCommand(OPEN_TOOL_INTEGRATION);
        toolIntegrationBtn.addActionListener(new ButtonClickListener());

        JButton prefDiagBtn = new JButton("View pref diagram");
        prefDiagBtn.setActionCommand(VIEW_PREF);
        prefDiagBtn.addActionListener(new ButtonClickListener());

        JButton userInsertRuleBtn = new JButton("Insert new rule");
        userInsertRuleBtn.setActionCommand(USER_INSERT_RULE_START);
        userInsertRuleBtn.addActionListener(new ButtonClickListener());

        JButton ruleSearchBtn = new JButton(DISPLAY_RULES);
        ruleSearchBtn.setActionCommand(DISPLAY_RULES);
        ruleSearchBtn.addActionListener(new ButtonClickListener());


        JPanel topPanel = defaultJPanel();
        topPanel.add(toolIntegrationBtn);
        topPanel.add(prefDiagBtn);
        topPanel.add(userInsertRuleBtn);
        topPanel.add(ruleSearchBtn);

        mainFrame.add(topPanel);
        mainFrame.add(new JSeparator());
        mainFrame.add(new JLabel("\t\tName of attack (No spaces or '.'):", JLabel.LEFT));
        mainFrame.add(panel2);
        mainFrame.add(panel3);
        mainFrame.add(panel3b);
        mainFrame.add(new JSeparator());
        mainFrame.add(panel4);
        mainFrame.add(new JSeparator());

        mainFrame.add(new JLabel("\t\tInput evidence: ", JLabel.LEFT));
        mainFrame.add(panel5a);
        mainFrame.add(panel5b);
        mainFrame.add(new JSeparator());
        mainFrame.add(new JLabel("\t\tInput so far:", JLabel.LEFT));
        mainFrame.add(scrollPane);

        mainFrame.add(panel6);
        mainFrame.add(status);

        defaultJFrameActions(mainFrame);
        System.out.println("Ready!");
    }

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

        panel5b.add(submitButton);
        panel5b.add(uploadButton);
        panel2.add(executeButton);
        panel3.add(new JLabel(EXECUTEALLINFO, JLabel.RIGHT));
        panel3.add(executeAllButton);
        panel3b.add(new JLabel("Possible culprits (separate by commas):"));
        panel3b.add(possibleCulprits);
        panel4.add(customQueryExecuteButton);
        panel6.add(updateButton);
        mainFrame.setVisible(true);
    }

    private void choosePreferenceAction(String command, int type) {
        String[] s = command.split("\\*");
        String selectedDer = s[0];
        String[] posDers = s[1].split(SEPARATOR);

        System.out.println("select pref: "+ command + " type: " + type);


        JTextArea selectedDerTF = defaultTextArea(selectedDer, 50);


        JPanel prefP = new JPanel();
        prefP.setLayout(new BoxLayout(prefP, BoxLayout.Y_AXIS));
        prefP.add(new JLabel("Selected derivation:"));
        prefP.add(selectedDerTF);
        String finalStrRule = Result.getFinalRule(selectedDer);
        highlightWordInTextArea(finalStrRule, selectedDerTF, Color.YELLOW, false);

        prefP.add(new JLabel("Other derivations:"));
        for (String notSelectedDer : posDers) {
            List<String> conflictingRules = QueryExecutor.getConflictingRule(notSelectedDer, selectedDer);

            JButton choosePos = new JButton("Prefer " + conflictingRules.get(0));
            JButton chooseNeg = new JButton("Prefer " + conflictingRules.get(1));
            choosePos.setActionCommand("Choose:" + type + ":" + conflictingRules.get(0) + ">" + conflictingRules.get(1));
            chooseNeg.setActionCommand("Choose:" + type + ":" + conflictingRules.get(1) + ">" + conflictingRules.get(0));
            choosePos.addActionListener(new ButtonClickListener());
            chooseNeg.addActionListener(new ButtonClickListener());

            JTextArea notSelectedDTF = defaultTextArea(notSelectedDer, 50);
            String otherFinalStrRule = Result.getFinalRule(notSelectedDer);
            highlightWordInTextArea(otherFinalStrRule, notSelectedDTF, Color.YELLOW, false);

            JPanel btnPanel = defaultJPanel();
            btnPanel.add(chooseNeg);
            btnPanel.add(choosePos);

            prefP.add(notSelectedDTF);
            prefP.add(btnPanel);
        }

        JScrollPane prefSP = new JScrollPane(prefP);
        prefFrame = new JFrame("Set new pref");
        prefFrame.add(prefSP);
        defaultJFrameActions(prefFrame);
//        prefFrame.setSize(1200, 400);
    }

    private void openToolIntegrationWindow() {
        logAttackname = new JTextField();
        toolIntegrationStatus = new JLabel();
        JButton btn = new JButton(UPLOAD_LOG);
        btn.setActionCommand(UPLOAD_LOG);
        btn.addActionListener(new ButtonClickListener());

        toolIntegrationFrame = new JFrame("Forensic tool integration");
//        toolIntegrationFrame.setLayout(new BoxLayout(toolIntegrationFrame.getContentPane(), BoxLayout.Y_AXIS));
        toolIntegrationFrame.add(new JLabel("Attack name associated with log:"));
        toolIntegrationFrame.add(logAttackname);
        toolIntegrationFrame.add(toolIntegrationStatus);
        toolIntegrationFrame.add(btn);
//        toolIntegrationFrame.setVisible(true);
        defaultJFrameActions(toolIntegrationFrame);
        toolIntegrationFrame.setSize(400,200);
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
                executeResult = qe.executeAll(attackName.getText(), culpritsToConsider);
//
//                if (jc == null) {
//                    jc = new JasperCallable();
//                }
//                jc.setName(attackName.getText());
//                jc.setReload(true);
//                jc.setAll(true);
//                if (culpritsToConsider.size() > 0) {
//                    jc.setCulpritsList(culpritsToConsider);
//                }
//                executeResult = jc.call();

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
                executeResult = qe.execute(attackName.getText(), true, new ArrayList<>());
            } catch (Exception e) {
                e.printStackTrace();
            }
//            try {
//                if (jc == null) {
//                    jc = new JasperCallable();
//                }
//                jc.setName(attackName.getText());
//                jc.setReload(true);
//                jc.setAll(all);
//                executeResult = jc.call();
//            } catch (Exception e1) {
//                e1.printStackTrace();
//            }

            if (!all) {
                displayExecutionResult(executeResult);
            } else {
                displayResultsAndNonResults();

            }
        }
    }

    private void displayExecutionResult(Result executeResult) {
        reloadResult = executeResult;
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        executeResult.filterByStrRulePrefs(strRulePrefs);
        List<Pair<String, Pair<List<String>, String>>> rs = executeResult.resultStrings();
        int c = 0;

        String summary = executeResult.getCulpritsSummary();
        if (summary.trim().length() == 0) {
            summary = "No results for execution. Try clicking 'Prove all possible predicates' to see what other evidence can be provided.";
        }

        JLabel label = new JLabel("User preferences:");
        p.add(label);
        p.add(defaultTextArea(strRulePrefs.toString(), 40));

        JLabel label2 = new JLabel("Summary:");
        p.add(label2);
        p.add(defaultTextArea(summary, 50));

        if (executeResult.hasAbduced()) {
            JLabel label3 = new JLabel("Assumptions:");
            p.add(label3);
            p.add(defaultTextArea(executeResult.getAbducedInfo(), 50));
        }

        JLabel label4 = new JLabel("Derivations:");
        p.add(new JSeparator());
        p.add(label4);

        for (int i = 0; i < rs.size(); i++) {
            String r = rs.get(i).getKey();
            JTextArea textArea = defaultTextArea(r, 50);
            highlightWordInTextArea("X = [(A-Z)|(a-z)|_]*\\b", textArea, Color.YELLOW, true); // highlight culprit
            JButton viewDiagBtn = new JButton("View Diagram");
            String filename = DerivationNode.getDiagramFilename(executeResult.getAttack(), c);
            viewDiagBtn.setActionCommand(filename);
            viewDiagBtn.addActionListener(new ButtonClickListener());

            JButton viewTreeBtn = new JButton("View Argumentation Tree");
            viewTreeBtn.setActionCommand(ARG_TREE + "arg_tree_" + i + ".svg:" +  executeResult.getTree(i));
            viewTreeBtn.addActionListener(new ButtonClickListener());


            JPanel btnPanel = defaultJPanel();

            btnPanel.add(viewDiagBtn);
            btnPanel.add(viewTreeBtn);

            if (rs.size() > 1) {
                JButton addPrefBtn = new JButton("Add rule preference");
                addPrefBtn.setActionCommand(PREF_TYPE + 1 + ADD_PREF + rs.get(i).getValue().getKey() + "*"
                        + executeResult.getDerivationsWithDiffStrRule(SEPARATOR, i));
                addPrefBtn.addActionListener(new ButtonClickListener());
                btnPanel.add(addPrefBtn);
            }

            p.add(textArea);
            p.add(btnPanel);
            c++;
        }

        if (executeResult.hasNegDerivations()) {
            p.add(new JSeparator());
            p.add(new JLabel("Negative Derivations: " + executeResult.getNumNegDerivations()));
        }

        for (String culprit : executeResult.getCulprits()) {
            for (String nd : executeResult.negDerivationFor(culprit)) {
                p.add(new JLabel(String.format("neg(isCulprit(%s,%s))", culprit, attackName.getText())));
                p.add(defaultTextArea(nd, -1));
                JButton addPrefBtn = new JButton("Add rule preference");
                addPrefBtn.setActionCommand(PREF_TYPE + 0 + ADD_PREF + nd + "*" + executeResult.getDerivationsForCulprit(culprit, SEPARATOR));
                addPrefBtn.addActionListener(new ButtonClickListener());
                p.add(addPrefBtn);
            }
        }
        JScrollPane scrollPane = new JScrollPane(p);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        executeResultFrame = new JFrame("Execution Result for " + attackName.getText());
        executeResultFrame.add(scrollPane);
        defaultJFrameActions(executeResultFrame);
    }

    private void displayResultsAndNonResults() {
        String allStrRules = utils.getAllStrRules();
        String[] strRules = allStrRules.split("\n");
        JFrame altDispFrame = new JFrame("Possible evidences");
        JPanel container = new JPanel();
        container.setLayout(new BoxLayout(container, BoxLayout.Y_AXIS));
//        altDispFrame.setLayout(new BoxLayout(altDispFrame.getContentPane(), BoxLayout.Y_AXIS));

        try {
            for (String strRule : strRules) {
                if (strRule.length() > 0) {
                    JTextArea ta = defaultTextArea(strRule, 120);

                    JButton btn = new JButton("Details");
                    btn.setActionCommand(DISPLAY_RESULTS + strRule);
                    btn.addActionListener(new ButtonClickListener());

                    Pair<List<String>, List<String>> r = QueryExecutor.tryToProve(strRule, attackName.getText());
                    for (String proven : r.getKey()) {
                        String provenPred = proven.substring(0, proven.lastIndexOf("(") + 1);
                        highlightWordInTextArea(provenPred, ta, Color.green, false);
                    }
                    for (String notProven : r.getValue()) {
                        String notProvenPred = notProven.substring(0, notProven.lastIndexOf("(") + 1);
                        highlightWordInTextArea(notProvenPred, ta, Color.pink, false);
                    }

                    JPanel p = defaultJPanel();
                    p.add(ta);
                    p.add(btn);
//                    altDispFrame.add(p);
                    container.add(p);
                }
            }
            JScrollPane sp = new JScrollPane(container);
            sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            altDispFrame.add(sp);
            defaultJFrameActions(altDispFrame);
        } catch (Exception e) {
            e.printStackTrace();
        }
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


    static void highlightWordInTextArea(String word, JTextArea textArea, Color colour, boolean useRegex) {
        String text = textArea.getText();
        Highlighter highlighter = textArea.getHighlighter();
        Highlighter.HighlightPainter painter =
                new DefaultHighlighter.DefaultHighlightPainter(colour);

        try {
            if (!useRegex) {
                String[] lines = text.split("\n");
                int p0 = text.indexOf(word);
                int p1;
                while (p0 >= 0) {
                    p1 = p0 + word.length();
                    highlighter.addHighlight(p0, p1, painter);
                    p0 = text.indexOf(word, p0 + 1);
                }
            } else {
                Pattern pattern = Pattern.compile(word);
                Matcher matcher = pattern.matcher(text);
                int p0, p1;
                String matched;
                while (matcher.find()) {
                    matched = matcher.group();
                    p0 = matcher.start();
                    p1 = p0 + matched.length();
                    highlighter.addHighlight(p0, p1, painter);
                }
            }
        } catch (BadLocationException e) {
            e.printStackTrace();
        }
    }


    void insertNewRuleAndSetPref() {
        insertNewRuleFrame = new JFrame("Add new rule");
//        insertNewRuleFrame.setLayout(new BoxLayout(insertNewRuleFrame.getContentPane(), BoxLayout.Y_AXIS));

        JPanel p = defaultJPanel();
        userNewRule = new JTextField();
        userNewRule.setColumns(40);
        JButton submitRuleBtn = new JButton("Done");
        submitRuleBtn.setActionCommand(USER_INSERT_RULE);
        submitRuleBtn.addActionListener(new ButtonClickListener());

        p.add(new JLabel("New rule (in prolog style):"));
        p.add(userNewRule);
        p.add(submitRuleBtn);

        userRuleConflictStatus = new JTextArea();
        userRuleConflicts = new JPanel();
        insertNewRuleFrame.add(p);
        insertNewRuleFrame.add(userRuleConflictStatus);
        insertNewRuleFrame.add(userRuleConflicts);
        defaultJFrameActions(insertNewRuleFrame);
    }

    private void showConflictingRules(String rule) {
        String headPred = Utils.getHeadPredicateOfPrologRule(rule);
        String negPred;
        if (headPred.contains("neg(")) {
            negPred = headPred.split("neg\\(")[1];
        } else {
            negPred = "neg(" + headPred;
        }

        List<String> allRules = Utils.getAllRulesWithHeadPred(negPred);
        userRuleConflicts.removeAll();
        userRuleConflicts.setLayout(new BoxLayout(userRuleConflicts, BoxLayout.Y_AXIS));

        userRuleConflicts.add(new JLabel(allRules.size() + " conflicts found!"));
        for (String r : allRules) {

            JTextArea rta = defaultTextArea(r, 100);

            String p0rulename = utils.getCurrentUserEvidenceRulename();
            String p1rulename = Utils.getRulenameOfLine(r);

            JPanel btnPanel = defaultJPanel();

            JButton p0Btn = new JButton("Prefer new rule");
            p0Btn.setActionCommand(USER_INSERT_RULE + p0rulename + SEPARATOR + p1rulename);
            p0Btn.addActionListener(new ButtonClickListener());

            JButton p1Btn = new JButton("Prefer " + p1rulename);
            p1Btn.setActionCommand(USER_INSERT_RULE + p1rulename + SEPARATOR + p0rulename);
            p1Btn.addActionListener(new ButtonClickListener());

            btnPanel.add(p0Btn);
            btnPanel.add(p1Btn);
            userRuleConflicts.add(rta);
            userRuleConflicts.add(btnPanel);
        }
        insertNewRuleFrame.pack();
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
                        System.out.println("Opening: " + file.getPath() + ".");
                        status.setText("Uploaded file: " + file.getPath());
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
                        c = c.trim();
                        if (c.length() > 0) {
                            csList.add(c);
                        }
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
                    String res = qe.executeCustomQuery(customQuery);
                    if (res == null || res.equals("")) {
                        res = "False. No result for: " + customQuery;
                    }

                    JPanel p = new JPanel();
                    p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
                    p.add(defaultTextArea(res, 40));

                    JScrollPane sp = new JScrollPane(p);
                    sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

                    JFrame f = new JFrame("Custom query result for " + customQuery);
                    f.add(sp);
                    defaultJFrameActions(f);
                    break;
                case UPLOAD_LOG:
                    if (logAttackname.getText().length() == 0) {
                        toolIntegrationStatus.setText("\t\tPlease input name of attack associated with squid log");
                        highlightElement(logAttackname);
                        return;
                    }

                    returnVal = fileChooser.showOpenDialog(toolIntegrationFrame);

                    if (returnVal == JFileChooser.APPROVE_OPTION) {
                        File file = fileChooser.getSelectedFile();
                        System.out.println("Opening: " + file.getPath());
                        displaySnortLogs(ToolIntegration.parseSnortLogs(file));
                        status.setText("Processed Snort alert file " + file + " for attack " + logAttackname.getText());
                    }
                    break;
                case OPEN_TOOL_INTEGRATION:
                    System.out.println("Opening tool integration");
                    openToolIntegrationWindow();
                    break;
                case VIEW_PREF:
                    PrefDiagramNode.createPreferenceDiagram();
                    SVGApplication.displayFile("img/pref_diagram.svg");
                    break;
                case USER_INSERT_RULE:
                    utils.addRules(userNewRule.getText());
                    currentEvidences.setText(utils.getCurrentEvidence());
                    showConflictingRules(userNewRule.getText());
                    break;
                case USER_INSERT_RULE_START:
                    insertNewRuleAndSetPref();
                    break;
                case DISPLAY_RULES:
                    displayRules();
                    break;
                case DISPLAY_RULE_SEARCH:
                    String rulename = displayRulesTextField.getText();
                    displayRulesFrame.add(new JLabel(Utils.getRuleFromRulename(rulename)));
                    displayRulesFrame.add(new JLabel());
                    displayRulesFrame.pack();
                    break;
                default:
                    System.out.println("Command:" + command);

                    if (command.startsWith(PREF_TYPE)) {
                        // auto add pref
                        int prefType = Integer.parseInt(command.substring(command.indexOf(PREF_TYPE) + PREF_TYPE.length(), command.indexOf(ADD_PREF)));
                        choosePreferenceAction(command.split(ADD_PREF)[1], prefType);
                    } else if (command.startsWith(DISPLAY_RESULTS)) {
                        // details page for execute all
                        String strRule = command.split(DISPLAY_RESULTS)[1];
                        try {
                            Pair<List<String>, List<String>> r = QueryExecutor.tryToProve(strRule, attackName.getText());
                            Map<String, List<String>> allRules = QueryExecutor.getPredMap(r.getValue(), false);
                            JTextArea possibleRulesTA = defaultTextArea(Utils.formatMap(allRules), 120);
                            for (String head : allRules.keySet()) {
                                String headWithConst = returnMatchingPredicate(head, r.getValue());
                                List<String> rules = allRules.get(head);
                                for (String rule : rules) {
                                    Pair<List<String>, List<String>> pair = QueryExecutor.tryToProve(rule, attackName.getText(), headWithConst);
                                    for (String pair0 : pair.getKey()) {
                                        pair0 = pair0.substring(0, pair0.lastIndexOf("(") + 1);
                                        highlightWordInTextArea(pair0, possibleRulesTA, Color.green, false);
                                    }
                                    for (String pair1 : pair.getValue()) {
                                        pair1 = pair1.substring(0, pair1.lastIndexOf("(") + 1);
                                        highlightWordInTextArea(pair1, possibleRulesTA, Color.pink, false);
                                    }
                                }
                            }

                            JFrame frame = new JFrame("Details:");
//                            frame.setLayout(new BoxLayout(frame.getContentPane(), BoxLayout.Y_AXIS));
                            frame.add(new JLabel("Proven"));
                            frame.add(defaultTextArea(String.valueOf(r.getKey()), 120));
                            frame.add(new JLabel("Not proven"));
                            frame.add(defaultTextArea(String.valueOf(r.getValue()), 120));
                            frame.add(new JLabel("Possible rules:"));
                            frame.add(possibleRulesTA);
                            defaultJFrameActions(frame);

                        } catch (Exception e1) {
                            e1.printStackTrace();
                        }
                    } else if (command.startsWith(USER_INSERT_RULE)) {
                        // user insert new rule resolve conflicts
                        command = command.split(USER_INSERT_RULE)[1];

                        String[] s = command.split(SEPARATOR);
                        String chosen = s[0];
                        String other = s[1];
                        String preference = String.format("prefer(%s,%s)", chosen, other);
                        utils.writePrefToFile(preference);
                        currentEvidences.setText(utils.getCurrentEvidence());
                        userRuleConflictStatus.setText(userRuleConflictStatus.getText() + preference + " added!\n");
                        insertNewRuleFrame.pack(); //FIXME

                    } else if (command.startsWith("Choose:")) {
                        // create preference rule
                        String[] s = command.split(":")[2].split(">");
                        String pref = String.format("prefer(%s,%s)", s[0], s[1]);
                        if (Integer.parseInt(command.split(":")[1]) == 0) {
                            utils.writePrefToFile(pref);
                            currentEvidences.setText(utils.getCurrentEvidence());
                            executeResultFrame.dispose();
                            executeQuery(false);
                            prefFrame.dispose();
                            strRulePrefs.add(new Pair<>(s[1], s[0]));
                            status.setText("Added  " + pref + " to " + Utils.USER_EVIDENCE_FILENAME);
                        } else {
                            prefFrame.dispose();
                            executeResultFrame.dispose();
                            strRulePrefs.add(new Pair<>(s[0], s[1]));
                            status.setText("Str rule preference: " + pref);
                            displayExecutionResult(reloadResult);
                        }

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

    // separate frame to search (by rulename) and display rules
    private void displayRules() {
        displayRulesTextField = new JTextField();
        displayRulesTextField.setColumns(50);
        JButton btn = new JButton("Search");
        btn.setActionCommand(DISPLAY_RULE_SEARCH);
        btn.addActionListener(new ButtonClickListener());

        displayRulesFrame = new JFrame("Search rules");
        displayRulesFrame.add(new JLabel("Input rulename to view entire rule"));
        displayRulesFrame.add(displayRulesTextField);
        displayRulesFrame.add(btn);
        displayRulesFrame.add(new JLabel("Results:"));
        displayRulesFrame.setAlwaysOnTop(true);
        defaultJFrameActions(displayRulesFrame);
    }

    private String returnMatchingPredicate(String head, List<String> hs) {
        for (String h : hs) {
            if (h.split("\\(")[0].equals(head.split("\\(")[0])) {
                return h;
            }
        }
        return "";
    }

    private static JTextArea defaultTextArea(String text, int cols) {
        JTextArea ta = new JTextArea(text);
        if (cols > 0) {
            ta.setColumns(cols);
        }
        ta.setEditable(false);
        ta.setLineWrap(true);
        ta.setCaretPosition(0);
        return ta;
    }

    private static void defaultJFrameActions(JFrame f) {
        f.setLayout(new BoxLayout(f.getContentPane(), BoxLayout.Y_AXIS));
        f.pack();
        f.setVisible(true);
    }

    private static JPanel defaultJPanel() {
        JPanel p = new JPanel();
        p.setLayout(new FlowLayout());
        return p;
    }

    // helper method for displaySnortLogs, create clickable string in JEditorPane using str as url
    private static String hyperlink(String str) {
        StringBuilder sb = new StringBuilder();
        sb.append("<a href='https://" + str + "'>");
        sb.append(str);
        sb.append("</a><br>");
        return sb.toString();
    }

    void displaySnortLogs(Map<String, Map<String, Map<String, Integer>>> snortOutput) {
        JEditorPane jep = new JEditorPane();
        jep.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        jep.setFont(status.getFont());
        jep.setContentType("text/html");
        StringBuilder sb = new StringBuilder();

        for (String srcIP : snortOutput.keySet()) {
            sb.append("src IP: " + hyperlink(srcIP));
            for (String destIP : snortOutput.get(srcIP).keySet()) {
                sb.append("&nbsp;&nbsp;dest IP:" + hyperlink(destIP));
                for (String msg : snortOutput.get(srcIP).get(destIP).keySet()) {
                    sb.append("&nbsp;&nbsp;&nbsp;&nbsp;Msg: " + msg + "(" + snortOutput.get(srcIP).get(destIP).get(msg) + ")<br><br>");
                }
            }
            sb.append("<hr>");
        }

        jep.setText(sb.toString());
        jep.setEditable(false);
        jep.addHyperlinkListener(e -> {
            if (HyperlinkEvent.EventType.ACTIVATED.equals(e.getEventType())) {
                String ipString = e.getURL().getHost().replace(".", ",");
                String fact = String.format("attackSourceIP([%s], %s)", ipString, logAttackname.getText());
                utils.addRules(fact);
                fact = String.format("ip([%s])", ipString);
                utils.addRules(fact);
                currentEvidences.setText(utils.getCurrentEvidence());
                logStatus.setText(logStatus.getText() + fact + " added!\n");
            }
        });

        JScrollPane sp = new JScrollPane(jep);
        sp.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        JLabel label = new JLabel("Click on IPs to add attackSourceIP(<IP>," + logAttackname.getText() + ") as evidence.");
        label.setBackground(Color.YELLOW);
        label.setOpaque(true);
        label.setFont(label.getFont().deriveFont(16));
        logStatus = new JTextArea();
        logStatus.setEditable(false);
        logStatus.setBackground(Color.lightGray);
        JFrame f = new JFrame("Processed snort log");

        f.add(label);
        f.add(logStatus);
        f.add(sp);
        defaultJFrameActions(f);
    }

    public static void main(String args[]) {
        GUI awt = new GUI();
//        awt.displaySnortLogs(ToolIntegration.parseSnortLogs("/Users/linna/Downloads/tg_snort_full/alert.full"));
    }
}
