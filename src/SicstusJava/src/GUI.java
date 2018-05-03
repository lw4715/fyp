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
    private static final String EXECUTEALLINFO = "(Get a list of predicates that can be derived by current evidences)";
//    private static final String VIEWDIAGRAM = "ViewDiagram_";

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
    private JScrollPane scrollPane;
    private JasperCallable jc;
    private Map<String, Result> accumulatedResults;
    private final JFileChooser fileChooser = new JFileChooser();

    private static final String[] placeholderItem = {"Select from existing predicates"};

    private static final String[] predicates = {"industry(<T>)","targetCountry(<X>>,<<Att>)",
            "fileChara(<Filename>,<MD5>,<Size>,<CompileTime>,<Desc>,<Filetype>,<C1>)","poorRelation(<C>,<T>)",
            "noPriorHistory(<X>)","infraUsed(<Infra>,<Att>)","hasResources(<X>)","majorityIpOrigin(<X>,<Att>)",
            "stolenValidSignedCertificates(<Att>)","cybersuperpower(<X>)","espionage>,<doxing>)",
            "attackPeriod(<Att>,<[Year>,<Month]>)","governmentLinked(<P>,<C>)",
            "domainRegisteredDetails(<Server>,<Name>,<Addr>)","ipResolution(<S>,<IP>,<D>)",
            "infectionMethod(<usb>,<M>)","attackOrigin(<X>,<Att>)","highLevelSkill(<Att>)",
            "usesZeroDayVulnerabilities(<M>)","hasPoliticalMotive(<C>,<T>,<Date2>)",
            "malwareUsedInAttack(<M>,<Att>)","news(<News>,<T>,<Date2>)","prominentGroup(<X>)",
            "attackPossibleOrigin(<X>,<Att>)","notForBlackMarketUse(<M>)","similarCCServer(<M1>,<M2>)",
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

        JComboBox dropdown = new JComboBox(predicates);
        dropdown.addItemListener(arg0 -> {
            resetColours();
            status.setText("\t\tSelected: " + dropdown.getSelectedItem());
            evidence.setText(dropdown.getSelectedItem().toString());

        });
        dropdown.setSize(70,0);

        evidence = new JTextField(placeholderItem[0]);
        evidence.setColumns(35);
        attackName = new JTextField(JTextField.LEFT);
        attackName.setColumns(15);

        JComboBox existsingAttacks = new JComboBox(new String[] {"Select predefined attacks",
                "usbankhack", "apt1", "gaussattack", "stuxnetattack", "sonyhack", "wannacryattack"});
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
        currentEvidences.setRows(10);
        scrollPane = new JScrollPane(currentEvidences);
        scrollPane.setSize(0,300);

        panel1.add(dropdown);
        panel1.add(evidence);
        panel2.add(existsingAttacks);
        panel2.add(attackName);

        mainFrame.add(new JLabel("\t\tInput evidence: ", JLabel.LEFT));
        mainFrame.add(panel1);
        mainFrame.add(new JLabel("\t\tName of attack (No spaces or '.'):", JLabel.LEFT));
        mainFrame.add(panel2);
        mainFrame.add(panel3);

        mainFrame.add(new JLabel("\t\tEvidence so far:", JLabel.LEFT));
        mainFrame.add(scrollPane);

        mainFrame.add(panel4);
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
        panel3.add(executeAllButton);
        panel3.add(new JLabel(EXECUTEALLINFO, JLabel.RIGHT));
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
                case UPDATE:
                    status.setText(String.format("\t\tUpdated file: %s", utils.USER_EVIDENCE_FILENAME));
                    utils.updateEvidence(currentEvidences.getText());
                    accumulatedResults.clear();
                    break;
                default:
                    SVGApplication.displayFile("img/" + command);
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

                JPanel p = new JPanel();
                p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
                List<String> rs = executeResult.resultStrings();
                int c = 0;
                for (String r : rs) {
                    JTextArea textArea = new JTextArea();
                    textArea.setColumns(50);
//                    textArea.setRows(10);
                    textArea.setEditable(false);
                    textArea.setText(r);
                    textArea.setLineWrap(true);
                    JButton btn = new JButton("View diagram");
                    String filename = DerivationNode.getDiagramFilename(executeResult.getAttack(), c);
                    btn.setActionCommand(filename);
                    btn.addActionListener(new ButtonClickListener());
                    p.add(textArea);
                    p.add(btn, Panel.LEFT_ALIGNMENT);
                    c++;
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
                dialog.setSize(1200, 1000);
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
//        JScrollPaneDemo();
    }


    public static void JScrollPaneDemo() {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                // create a jtextarea
//                JPanel p = new JPanel();
//                p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
////                JTextArea t = new JTextArea();
////                t.setText("xx\nxx\nxx\nxx\nxx\nxx\nxx\nxx\nxx\nxx\nxx\nxx\nxx\nxx\n");
//                for (int i = 0; i < 10; i++) {
//                    JTextArea textArea = new JTextArea();
//                    textArea.setText("t is a long established fact that a reader will be distracted by the readable content of a page when looking at its layout. The point of using Lorem Ipsum is that it has a more-or-less normal distribution of letters, as opposed to using 'Content here, content here', making it look like readable English. Many desktop publishing packages and web page editors now use Lorem Ipsum as their default model text, and a search for 'lorem ipsum' will uncover many web sites still in their infancy. Various versions have evolved over the years, sometimes by accident, sometimes on purpose (injected humour and the like).t is a long established fact that a reader will be distracted by the readable content of a page when looking at its layout. The point of using Lorem Ipsum is that it has a more-or-less normal distribution of letters, as opposed to using 'Content here, content here', making it look like readable English. Many desktop publishing packages and web page editors now use Lorem Ipsum as their default model text, and a search for 'lorem ipsum' will uncover many web sites still in their infancy. Various versions have evolved over the years, sometimes by accident, sometimes on purpose (injected humour and the like).");
//                    p.add(textArea);
//                }
////                scrollPane.add(p);
//                JScrollPane scrollPane = new JScrollPane(p);
                JTextArea t = new JTextArea();
                // now add the scrollpane to the jframe's content pane, specifically
                // placing it in the center of the jframe's borderlayout
                JFrame frame = new JFrame("JScrollPane Test");
                frame.add(t, BorderLayout.LINE_START);
                frame.add(t, BorderLayout.CENTER);
//                frame.pack();
//                JOptionPane.showConfirmDialog(frame, scrollPane);
                // make it easy to close the application
                frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

                // set the frame size (you'll usually want to call frame.pack())
                frame.setSize(new Dimension(240, 180));

                // center the frame
                frame.setLocationRelativeTo(null);
                frame.pack();
                // make it visible to the user
                frame.setVisible(true);
            }
        });
    }
}