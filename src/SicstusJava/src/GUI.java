import javafx.util.Pair;

import javax.swing.*;
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
    private static final String UPLOAD_SQUID_LOG = "Upload squid log";
    private static final String OPEN_TOOL_INTEGRATION = "Open tool integration";
    private static final String ADD_PREF = "AddPref_";
    private static final String SEPARATOR = "#";
    private static final String PREF_TYPE = "PrefType_";

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
    private JTextField squidLogAttackname;
    private JTextArea currentEvidences;
    private JScrollPane scrollPane;
    private JasperCallable jc;

    private JFrame executeResultFrame;
    private JFrame prefFrame;
    private JFrame toolIntegrationFrame;
    private JLabel toolIntegrationStatus;

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

    GUI() {
        utils = new Utils();
        prepareGUI();
        addButtonsToPanel();
    }

    private void prepareGUI() {
        mainFrame = new JFrame("Argumentation-Based Reasoner (ABR)");

        mainFrame.setLayout(new BoxLayout(mainFrame.getContentPane(), BoxLayout.Y_AXIS));

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

        JButton toolIntegrationBtn = new JButton("Tool integration");
        toolIntegrationBtn.setActionCommand(OPEN_TOOL_INTEGRATION);
        toolIntegrationBtn.addActionListener(new ButtonClickListener());

        mainFrame.add(toolIntegrationBtn);

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

                    JFrame f = new JFrame("Custom query result");
                    f.add(sp);
                    f.setSize(1200,1000);
                    f.setVisible(true);
                    break;
                case UPLOAD_SQUID_LOG:
                    if (squidLogAttackname.getText().length() == 0) {
                        toolIntegrationStatus.setText("\t\tPlease input malware name associated with squid log");
                        highlightElement(squidLogAttackname);
                        return;
                    }

                    returnVal = fileChooser.showOpenDialog(toolIntegrationFrame);

                    if (returnVal == JFileChooser.APPROVE_OPTION) {
                        File file = fileChooser.getSelectedFile();
                        System.out.println("Opening: " + file.getPath());
                        ToolIntegration.parseSquidLogFile(file, squidLogAttackname.getText());
                        toolIntegrationFrame.dispose();
                        status.setText("Processed squid file, updated prolog file: "
                                + ToolIntegration.SQUID_LOG_RULES_PL + " for attack: " + squidLogAttackname.getText());
                    }
                    break;
                case OPEN_TOOL_INTEGRATION:
                    System.out.println("Opening tool integration");
                    openToolIntegrationWindow();
                    break;
                default:
                    // add pref
                    if (command.startsWith(PREF_TYPE)) {
                        System.out.println("Full command:" + command);
                        int prefType = Integer.parseInt(command.substring(command.indexOf(PREF_TYPE) + PREF_TYPE.length(), command.indexOf(ADD_PREF)));
                        choosePreferenceAction(command.split(ADD_PREF)[1], prefType);
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

    private void choosePreferenceAction(String command, int type) {
        String[] s = command.split("\\*");
        String selectedDer = s[0];
        String[] posDers = s[1].split(SEPARATOR);

        System.out.println("select pref: "+ command + " type: " + type);


        JTextArea ntf = new JTextArea(selectedDer);
        ntf.setColumns(30);
        ntf.setLineWrap(true);


        JPanel prefP = new JPanel();
        prefP.setLayout(new BoxLayout(prefP, BoxLayout.Y_AXIS));
        prefP.add(new JLabel("Selected derivation:"));
        prefP.add(ntf);
        prefP.add(new JLabel("Other derivations:"));
        for (String posDer : posDers) {
            List<String> conflictingRules = QueryExecutor.getConflictingRule(posDer, selectedDer);

            JButton choosePos = new JButton("Prefer " + conflictingRules.get(0));
            JButton chooseNeg = new JButton("Prefer " + conflictingRules.get(1));
            choosePos.setActionCommand("Choose:" + type + ":" + conflictingRules.get(0) + ">" + conflictingRules.get(1));
            chooseNeg.setActionCommand("Choose:" + type + ":" + conflictingRules.get(1) + ">" + conflictingRules.get(0));
            choosePos.addActionListener(new ButtonClickListener());
            chooseNeg.addActionListener(new ButtonClickListener());

            JTextArea ptf = new JTextArea(posDer);
            ptf.setColumns(30);
            ptf.setLineWrap(true);

            JPanel btnPanel = new JPanel();
            btnPanel.setLayout(new FlowLayout());
            btnPanel.add(chooseNeg);
            btnPanel.add(choosePos);

            prefP.add(ptf);
            prefP.add(btnPanel);
        }

        JScrollPane prefSP = new JScrollPane(prefP);
        prefFrame = new JFrame("Set new preference");
        prefFrame.add(prefSP);
        prefFrame.setSize(1000, 800);
        prefFrame.setVisible(true);
    }

    private void openToolIntegrationWindow() {
        squidLogAttackname = new JTextField();
        toolIntegrationStatus = new JLabel();
        JButton btn = new JButton("Upload SQUID log");
        btn.setActionCommand(UPLOAD_SQUID_LOG);
        btn.addActionListener(new ButtonClickListener());

        toolIntegrationFrame = new JFrame("Forensic tool integration");
        toolIntegrationFrame.setLayout(new BoxLayout(toolIntegrationFrame.getContentPane(), BoxLayout.Y_AXIS));
        toolIntegrationFrame.add(new JLabel("Attack name associated with log:"));
        toolIntegrationFrame.add(squidLogAttackname);
        toolIntegrationFrame.add(toolIntegrationStatus);
        toolIntegrationFrame.add(btn);
        toolIntegrationFrame.setSize(400,200);
        toolIntegrationFrame.setVisible(true);
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
                if (culpritsToConsider.size() > 0) {
                    jc.setCulpritsList(culpritsToConsider);
                }
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

        p.add(new JLabel("User preferences:"));
        JTextArea prefRules = new JTextArea(strRulePrefs.toString());
        prefRules.setColumns(40);
        prefRules.setLineWrap(true);
        prefRules.setCaretPosition(0);
        p.add(prefRules);

        p.add(new JLabel("Summary:"));
        JTextArea ta = new JTextArea();
        ta.setColumns(50);
        ta.setEditable(false);
        ta.setLineWrap(true);
        ta.setText(summary);
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
            String r = rs.get(i).getKey();
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

            JPanel btnPanel = new JPanel();
            btnPanel.setLayout(new FlowLayout());

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
                addPrefBtn.setActionCommand(PREF_TYPE + 0 + ADD_PREF + nd + "*" + executeResult.getDerivationsForCulprit(culprit, SEPARATOR));
                addPrefBtn.addActionListener(new ButtonClickListener());
                p.add(addPrefBtn);
            }
        }
        JScrollPane scrollPane = new JScrollPane(p);
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        executeResultFrame = new JFrame("Execution Result for " + attackName.getText());
        executeResultFrame.add(scrollPane);
        executeResultFrame.setSize(1200,800);
        executeResultFrame.setVisible(true);
    }

    private void displayResultsAndNonResults() {
        String allStrRules = utils.getAllStrRules();
        JTextArea allRulesVisual = new JTextArea(allStrRules);
        allRulesVisual.setColumns(80);
        allRulesVisual.setLineWrap(true);

        List<String>[] res = readFromResultAndNonResultFiles();
        JDialog dialog = new JDialog(mainFrame);
        JPanel row1 = new JPanel();
        row1.setLayout(new FlowLayout());

        dialog.setLayout(new BoxLayout(dialog.getContentPane(), BoxLayout.Y_AXIS));
        StringJoiner sj = new StringJoiner("\n");
        for (String s : res[0]) {
            sj.add(s);
            String predicate = s.substring(0, s.lastIndexOf("("));
            highlightWordInTextArea(predicate, allRulesVisual, Color.green);
        }
        JTextArea results = new JTextArea("Results (proven):\n\n" + sj);
        results.setEditable(false);
        results.setRows(10);
        results.setColumns(47);
        results.setCaretPosition(0);
        JScrollPane row1col1 = new JScrollPane(results);
        row1.add(row1col1);

        sj = new StringJoiner("\n");
        for (String s : res[1]) {
            sj.add(s);
            String predicate = s.substring(0, s.lastIndexOf("("));
            highlightWordInTextArea(predicate, allRulesVisual, Color.pink);
        }

        JTextArea nonresults = new JTextArea("Other possible predicates (not proven):\n\n" + sj);
        nonresults.setCaretPosition(0);
        JScrollPane row1col2 = new JScrollPane(nonresults);
        nonresults.setEditable(false);
        nonresults.setRows(10);
        nonresults.setColumns(47);
        row1.add(row1col2);

        JTextArea possiblerules = new JTextArea("Possible rules:\n" + Utils.formatMap(QueryExecutor.getPredMap(res[1], false)));
        possiblerules.setEditable(false);
        possiblerules.setColumns(90);
        possiblerules.setRows(20);
        possiblerules.setCaretPosition(0);
        JScrollPane row2 = new JScrollPane(possiblerules);

        dialog.add(allRulesVisual);
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

    static void highlightWordInTextArea(String word, JTextArea textArea, Color colour) {
        String text = textArea.getText();
        Highlighter highlighter = textArea.getHighlighter();
        Highlighter.HighlightPainter painter =
                new DefaultHighlighter.DefaultHighlightPainter(colour);

        word = "," + word;
        String[] lines = text.split("\n");
        int p0 = text.indexOf(word);
        int p1;
        try {
            while (p0 >= 0) {
                p1 = p0 + word.length();
                highlighter.addHighlight(p0, p1, painter);
                p0 = text.indexOf(word, p0 + 1);
            }
        } catch (BadLocationException e) {
            e.printStackTrace();
        }

//        try {
//            for (String line : lines) {
//                if (line.contains(word)) {
//                    int p = text.indexOf(line);
//                    int p0 = p + line.indexOf(word);
//                    int p1 = p0 + word.length();
//
//                    highlighter.addHighlight(p0, p1, painter);
//                }
//            }
//        } catch (BadLocationException e) {
//            System.err.println("Highlighter bad location!");
//            System.err.println(word + " not found in " + textArea.getText());
//        }
    }
}
