import java.io.*;
import java.util.*;

public class Utils {
    private static final String CASE_USER_F = "case_user_f";
    private static final String P_USER_ = "p_user_";
    static final String BACKGROUNDGORGIAS_PL = "backgroundgorgias_renumbered.pl";
    static final String EVIDENCE_PL = "evidence.pl";
    private static String FILEPATH = "";

    static final String USER_EVIDENCE_FILENAME = "user_evidence.pl";
    static final String VISUALLOG = "visual.log";
    static final String TECH = FILEPATH + "tech_rules.pl";
    static final String OP = FILEPATH + "op_rules.pl";
    static final String STR = FILEPATH + "str_rules.pl";
    static final String EVIDENCE_FILENAME = FILEPATH + "evidence.pl";

    // counter is index of latest rule
    private int counter;
    private int prefCount;
    private String allStrRules;

    Utils() {
        counter = 0;
        prefCount = 0;
        clearFile(USER_EVIDENCE_FILENAME);
    }

    void addEvidence(String evidence) {
        if (evidence.length() == 0) {
            return;
        }
        counter++;
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(USER_EVIDENCE_FILENAME, true));
            bw.write(String.format("rule(%s%d(), %s, []).\n", CASE_USER_F, counter, evidence));
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // counter is index of latest rule
    String getCurrentUserEvidenceRulename() {
        return CASE_USER_F + counter + "()";
    }

    void addRulesWithoutChange(String rule) {
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(USER_EVIDENCE_FILENAME, true));
            bw.write(rule);
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void addRuleWithRulename(String rule, String rulename) {
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(USER_EVIDENCE_FILENAME, true));
            String[] split = rule.replace(".", "").split(":-");
            String head = split[0];
            StringJoiner sj = new StringJoiner(",");
            for (int i = 1; i < split.length; i++) {
                sj.add(split[i]);
            }
            String body = sj.toString();
            bw.write(String.format("rule(%s(), %s, [%s]).\n", rulename, head, body));
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // counter is index of latest rule
    void addRules(String rule) {
        if (rule.length() == 0) {
            return;
        }
        counter++;
        addRuleWithRulename(rule, CASE_USER_F + counter);
    }

    static void clearFile(String f) {
        PrintWriter writer = null;
        try {
            writer = new PrintWriter(f);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        writer.print(":- multifile rule/3.\n");
        writer.close();
    }

    public void updateEvidence(String evidences) {
        clearFile(USER_EVIDENCE_FILENAME);
        addRulesWithoutChange(evidences);
    }

    public void updateRule(File file) {
        clearFile(USER_EVIDENCE_FILENAME);
        try {
            BufferedReader br = new BufferedReader(new FileReader(file));
            br.lines().forEach(rule -> addRules(rule.split("%")[0]));
            br.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getCurrentEvidence() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(USER_EVIDENCE_FILENAME));
            StringBuilder sb = new StringBuilder();
            br.lines().skip(1).forEach(x -> sb.append(x + "\n"));
            br.close();
            return sb.toString();
        } catch (FileNotFoundException e) {
            System.err.println("File not found " + USER_EVIDENCE_FILENAME);
            return "";
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    static String formatMap(Map<String, List<String>> abducedMap) {
        StringBuilder sb = new StringBuilder();
        for (String k : abducedMap.keySet()) {
            sb.append(k);
            sb.append(": {");
            for (String v : abducedMap.get(k)) {
                sb.append("\n\t");
                sb.append(v);
            }
            sb.append("}\n");
        }
        return sb.toString();
    }

    static boolean isRule(String s) {
        return s.startsWith("r_");
    }

    static boolean isStrRule(String s) {
        return s.startsWith("r_str_");
    }

    static boolean isFinalStrRule(String s) {
        return s.startsWith("r_str__");
    }

    static boolean isAss(String s) {
        return s.equals("ass") || s.equals("abducible");
    }

    static boolean isPreference(String r) {
        r = r.trim();
        return r.startsWith("p") || r.startsWith("ass(neg(prefer(");
    }

    static String getHead(String name, List<String> args) {
        name = name.trim();
        boolean isInstantiated = name.startsWith("case") || name.startsWith("bg") || isPreference(name);
        if (isAss(name)) {
            return args.get(0);
        }
        String f = GetFilenameForRule(name);

        try {
            Map<String, String> argsMap = new HashMap<>();

            BufferedReader br = new BufferedReader(new FileReader(f));
            String line = br.readLine();
            while (line != null) {
                if (line.startsWith("rule(" + name + "(")) {
                    String[] argVars = line.split("\\(")[2].split("\\)")[0].split(",");

                    if (isPreference(name)) {
                        String head = line.split("prefer\\(")[1]
                                .split("\\[")[0]
                                .trim();
                        return "prefer(" + removeLastComma(head);
                    } else if (!args.isEmpty()) {
                        // fill variables with constants from rulename
                        String[] s = line.split("\\)")[1].split("\\(");
                        String head = s[0].split(",")[1];
                        String[] headVar = s[1].split(",");
                        for (int i = 0; i < argVars.length; i++) {
                            String var = argVars[i];
                            if (!var.isEmpty()) {
                                argsMap.put(var, args.get(i));
                            }
                        }
                        StringJoiner sj = new StringJoiner(",");
                        for (String var : headVar) {
                            String v = argsMap.get(var) == null ? var : argsMap.get(var);
                            sj.add(v);
                        }
                        return head.trim() + "(" + sj + ")";
                    }  else if (isInstantiated) {
                        // variables are already instantiated
                        String head = line.split("\\)")[1]
                                .replaceFirst(",","")
                                .trim();
                        return head + ")";
                    } else {
                        System.err.println("what is this? " + name);
                    }
                }
                line = br.readLine();
            }
            br.close();
        } catch (Exception e) {
            System.err.println(f + " not found");
            e.printStackTrace();
        }
        System.err.println("Head not found: " + name + " file: " + f);
        return "";
    }

    private static String removeLastComma(String head) {
        return head.substring(0, head.lastIndexOf(","));
    }

    // returns body of rule corresponding to rulename
    static List<String> getBody(String r) {
        String f = GetFilenameForRule(r);
        try {
            List<String> l = new ArrayList<>();
            BufferedReader br = new BufferedReader(new FileReader(f));
            String line = br.readLine();
            while (line != null) {
                if (line.startsWith("rule(" + r + "(")) {
                    if (isPreference(r)) {
                        String[] s = getHead(r, new ArrayList<>()).replaceFirst("prefer\\(","").split("\\),");
                        for (String s1 : s) {
                            if (s1.charAt(0) == ',') {
                                s1 = s1.substring(1, s1.length());
                            }
                            s1 = s1.trim();
                            if (!s1.isEmpty()) {
                                l.add(s1.split("\\(")[0]);
                            }
                        }

                    } else {
                        for (String b : line.split("\\[")[1].split("\\]")[0].split("\\)")) {
                            b = b.split("\\(")[0].replaceFirst(",", "").trim();
                            if (b.length() > 0) {
                                l.add(b);
                            }
                        }
                    }
                    return l;
                }
                line = br.readLine();
            }
            br.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.err.println("Body not found: " + r + " file: " + f);
        return null;
    }


    static String GetFilenameForRule(String r) {
        if (r.startsWith("r_t_") || (isPreference(r) && r.endsWith("t"))) {
            return TECH;
        } else if (r.startsWith("r_op_") || (isPreference(r) && r.endsWith("op"))) {
            return OP;
        } else if (r.startsWith("r_str_") || isPreference(r)) {
            return STR;
        } else if (r.startsWith(ToolIntegration.CASE_SQUID_LOG)) {
            return ToolIntegration.SQUID_LOG_RULES_PL;
        } else if (r.startsWith(ToolIntegration.CASE_TOR_CHECK)) {
            return ToolIntegration.TOR_IP_FILE;
        } else if (r.startsWith(ToolIntegration.CASE_AUTOGEN_GEOLOCATION)) {
            return ToolIntegration.AUTOMATED_GEOLOCATION_PL;
        } else if (r.startsWith(CASE_USER_F) || r.startsWith(P_USER_)) {
            return USER_EVIDENCE_FILENAME;
        } else if (r.startsWith("case")) {
            return EVIDENCE_PL;
        } else if (r.startsWith("bg")) {
            return BACKGROUNDGORGIAS_PL;
        } else {
            System.err.println(r + " which file?");
            return "";
        }
    }

    private static String getAllPreds() {
        BufferedReader br;
        Set<String> preds = new HashSet<>();
        String[] files = new String[] {TECH, OP, STR, "backgroundgorgias_renumbered.pl"};
        try {
            for (String f : files) {
                br = new BufferedReader(new FileReader(f));
                br.lines().forEach(line -> {
                    line = line.split("%")[0];
                    if (line.startsWith("rule(") && line.contains("[")) {
                        String[] body = getBodiesOfLine(line);
                        for (String b : body) {
                            if (b.startsWith(",")) {
                                b = b.replaceFirst(",", "");
                            }
                            preds.add(b.trim() + ")");
                        }
                    }
                });
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        StringBuilder sb = new StringBuilder();
        for (String pred : preds) {
            sb.append(pred + "\n");
        }
        return sb.toString();
    }

    private static String[] getBodiesOfLine(String line) {
        return line.substring(line.indexOf('['), line.lastIndexOf(']')).split("\\)");
    }

    static String getHeadOfLine(String line) {
        line = line.replace(" ", "").replace("\t", "");
        return line.substring(line.indexOf("),") + 2, line.indexOf(",["));
    }

    static String getBodyOfLine(String line) {
        return line.substring(line.indexOf("[") + 1, line.indexOf("]"));
    }

    public static String getRulenameOfLine(String line) {
        final String RULE = "rule(";
        return line.substring(line.indexOf(RULE) + RULE.length(), line.indexOf(")") + 1);
    }

    static String getRuleFromFile(String rulename, int file) {
        String filename;
        switch(file) {
            case 0:
                filename = TECH;
                break;
            case 1:
                filename = OP;
                break;
            case 2:
                filename = STR;
                break;
            case -1:
                filename = USER_EVIDENCE_FILENAME;
                break;
            default:
                System.err.println("Invalid filecode: " + file);
                return null;
        }

        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            String next = br.readLine();

            while (next != null) {
                if (!next.startsWith("%") && next.contains(rulename.split("\\(")[0] + "(")) {
                    return next.split("%")[0];
                }
                next = br.readLine();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }

    public void writePrefToFile(String preference) {
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(USER_EVIDENCE_FILENAME, true));
            bw.write(String.format("rule(%s%d, %s, []).\n", P_USER_, prefCount, preference));
            bw.close();
            prefCount++;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getAllStrRules() {
        if (allStrRules == null) {
            List<String> rs = new ArrayList<>();
            StringBuilder sb = new StringBuilder();
            try {
                BufferedReader br = new BufferedReader(new FileReader(STR));
                br.lines().forEach(x -> {
                    if (x.startsWith("rule(r_str__")) {
//                        rs.add(x);
                        sb.append(x + "\n");
                    }
                });

            } catch (FileNotFoundException e) {
                e.printStackTrace();

            }
//            allStrRules = rs;
//            return rs;
            allStrRules = sb.toString();
            return sb.toString();
        } else {
            return allStrRules;
        }
    }

    public static String getHeadPredicateOfPrologRule(String prologRule) {
        String head = prologRule.split(":-")[0].trim();
        return head.substring(0, head.lastIndexOf("("));
    }

    // scan through tech_rules, op_rules, str_rules, backgroundgorgias_renumbered,
    // return all rules with head == headPred
    public static List<String> getAllRulesWithHeadPred(String headPred) {
        List<String> allRuleFilenames = new ArrayList<>();
        allRuleFilenames.add(TECH);
        allRuleFilenames.add(OP);
        allRuleFilenames.add(STR);
        allRuleFilenames.add(BACKGROUNDGORGIAS_PL);

        List<String> allRules = new ArrayList<>();
        try {
            for (String filename : allRuleFilenames) {
                BufferedReader br = new BufferedReader(new FileReader(filename));

                br.lines().forEach(line -> {
                    line = line.split("%")[0].replace(" ", "").replace("\t", "");
                    if (line.startsWith("rule(")) {
                        String lineHead = getHeadOfLine(line);
                        if (lineHead.substring(0, lineHead.lastIndexOf("(")).equals(headPred)) {
                            allRules.add(line);
                        }
                    }

                });
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return allRules;
    }

    public static void main(String[] args) {
        System.out.println(getAllRulesWithHeadPred("hasMotive"));
    }

}
