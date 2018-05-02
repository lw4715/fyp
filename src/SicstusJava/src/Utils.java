import java.io.*;
import java.util.*;

public class Utils {
    static final String PROLOG_USER_EVIDENCE = "user_evidence";
    static final String USER_EVIDENCE_FILENAME = PROLOG_USER_EVIDENCE + ".pl";
    static final String VISUALLOG = "visual.log";
    private static String FILEPATH = "";
    static final String TECH = FILEPATH + "tech_rules";
    static final String OP = FILEPATH + "op_rules";
    static final String STR = FILEPATH + "str_rules";
    int counter;
    Utils() {
        counter = 0;
        clearFile();
    }

    void addEvidence(String evidence) {
        if (evidence.length() == 0) {
            return;
        }
        counter++;
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(USER_EVIDENCE_FILENAME, true));
            bw.write(String.format("rule(case_user_f%d(), %s, []).\n", counter, evidence));
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
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

    void addRules(String rule) {
        if (rule.length() == 0) {
            return;
        }
        counter++;
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(USER_EVIDENCE_FILENAME, true));
            String[] split = rule.replace(".", "").split(":-");
            String head = split[0];
            StringJoiner sj = new StringJoiner(",");
            for (int i = 1; i < split.length; i++) {
                sj.add(split[i]);
            }
            String body = sj.toString();
            bw.write(String.format("rule(case_user_f%d, %s, [%s]).\n", counter, head, body));
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    void clearFile() {
        PrintWriter writer = null;
        try {
            writer = new PrintWriter(USER_EVIDENCE_FILENAME);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        writer.print(":- multifile rule/3.\n");
        writer.close();
    }

    public void updateEvidence(String evidences) {
        clearFile();
        addRulesWithoutChange(evidences);
    }

    public void updateRule(File file) {
        clearFile();
        try {
            BufferedReader br = new BufferedReader(new FileReader(file));
            br.lines().forEach(rule -> addRules(rule.split("%")[0]));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public String getCurrentEvidence() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(USER_EVIDENCE_FILENAME));
            StringBuilder sb = new StringBuilder();
            br.lines().skip(1).forEach(x -> sb.append(x + "\n"));
            return sb.toString();
        } catch (FileNotFoundException e) {
            System.out.println("File not found");
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

    static boolean isAss(String s) {
        return s.startsWith("ass(") || s.equals("ass");
    }

    static boolean isPreference(String r) {
        return r.startsWith("p");
    }

    static String getHead(String name, List<String> args) {
        boolean isInstantiated = name.startsWith("case") || name.startsWith("bg") || isPreference(name);
        if (isAss(name)) return args.get(0);
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
                        System.out.println("what is this? " + name);
                    }
                }
                line = br.readLine();
            }
        } catch (Exception e) {
            System.out.println(f + " not found");
            e.printStackTrace();
        }
        System.out.println("Head not found: " + name + " file: " + f);
        return "";
    }

    private static String removeLastComma(String head) {
        return head.substring(0, head.lastIndexOf(","));
    }

    static List<String> getBody(String r) {
        String f = GetFilenameForRule(r);
        try {
            List<String> l = new ArrayList<>();
//            String[] rule = r.split("\\(");
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
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("Body not found: " + r + " file: " + f);
        return null;
    }


    static String GetFilenameForRule(String r) {
        if (r.startsWith("r_t_") || (isPreference(r) && r.endsWith("t"))) {
            return TECH + ".pl";
        } else if (r.startsWith("r_op_") || (isPreference(r) && r.endsWith("op"))) {
            return OP + ".pl";
        } else if (r.startsWith("r_str_") || isPreference(r)) {
            return STR + ".pl";
        } else if (r.startsWith("case_user_f")) {
            return USER_EVIDENCE_FILENAME;
        } else if (r.startsWith("case")) {
            return "evidence.pl";
        } else if (r.startsWith("bg")) {
            return "backgroundgorgias_renumbered.pl";
        } else {
            System.out.println(r + " which file?");
            return "";
        }
    }
}
