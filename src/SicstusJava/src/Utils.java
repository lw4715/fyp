import java.io.*;
import java.util.*;

public class Utils {
    static final String PROLOG_USER_EVIDENCE = "user_evidence";
    static final String USER_EVIDENCE_FILENAME = PROLOG_USER_EVIDENCE + ".pl";
    static final String VISUALLOG = "visual.log";
    private static String FILEPATH = "";
    static final String TECH = Utils.FILEPATH + "tech_rules";
    static final String OP = Utils.FILEPATH + "op_rules";
    static final String STR = Utils.FILEPATH + "str_rules";
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
        return s.startsWith("ass(");
    }

    static String getHead(String r) {
        if (!(r.startsWith("case") || r.startsWith("bg") || r.startsWith("r_"))) return r;


        String f = GetFilenameForRule(r);
        try {
            String[] rule = r.split("\\(");
            Map<String, String> argsMap = new HashMap<>();
            String[] args = rule[1].split(",");

            BufferedReader br = new BufferedReader(new FileReader(f));
            String line = br.readLine();
            while (line != null) {
                if (line.startsWith("rule(" + rule[0])) {
                    String[] argVars = line.split("\\(")[2].split("\\)")[0].split(",");

                    if (r.startsWith("r_")) {
                        // fill variables with constants from rulename
                        String head = line.split("\\)")[1].split("\\(")[0].split(",")[1];
                        String[] headVar = line.split("\\)")[1].split("\\(")[1].split(",");
                        for (int i = 0; i < argVars.length; i++) {
                            String var = argVars[i];
                            if (var.length() > 0)
                                argsMap.put(var, args[i].replace(")", ""));
                        }
                        System.out.println("args:" + argsMap);
                        StringJoiner sj = new StringJoiner(",");
                        for (String var : headVar) {
                            sj.add(argsMap.get(var));
                        }
                        return head.replace(" ", "") + "(" + sj + ")";
                    } else if (r.startsWith("case") || r.startsWith("bg")) {
                        // variables are already instantiated
                        String head = line.split("\\)")[1].replace(",","").replace(" ","");
                        return head + ")";
                    } else {
                        System.out.println("what is this? " + r);
                    }
                }
                line = br.readLine();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(r + " file: " + f);
        return "";
    }

    static List<String> getBody(String r) {
        String f = GetFilenameForRule(r);
        try {
            List<String> l = new ArrayList<>();
            String[] rule = r.split("\\(");
            BufferedReader br = new BufferedReader(new FileReader(f));
            String line = br.readLine();
            while (line != null) {
                if (line.startsWith("rule(" + rule[0])) {
                    for (String b : line.split("\\[")[1].split("\\]")[0].split("\\)")) {
                        System.out.println(b);
                        b = b.split("\\(")[0];
                        b = b.replace(" ", "");
                        b = b.replace(",", "");
                        b = b.replace("\t","");
                        if (b.length() > 0) {
                            l.add(b);
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
        System.out.println(r + " file: " + f);
        return null;
    }



    static String GetFilenameForRule(String r) {
        if (r.startsWith("r_t_")) {
            return TECH + ".pl";
        } else if (r.startsWith("r_op_")) {
            return OP + ".pl";
        } else if (r.startsWith("r_str_")) {
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
