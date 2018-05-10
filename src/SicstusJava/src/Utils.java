import java.io.*;
import java.util.*;

public class Utils {
    private static final String CASE_USER_F = "case_user_f";
    private static final String P_USER_ = "p_user_";
    private static String FILEPATH = "";

    static final String PROLOG_USER_EVIDENCE = "user_evidence";
    static final String USER_EVIDENCE_FILENAME = PROLOG_USER_EVIDENCE + ".pl";
    static final String VISUALLOG = "visual.log";
    static final String TECH = FILEPATH + "tech_rules";
    static final String OP = FILEPATH + "op_rules";
    static final String STR = FILEPATH + "str_rules";
    static final String EVIDENCE_FILENAME = FILEPATH + "evidence.pl";

    private int counter;
    private int prefCount;

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
            bw.write(String.format("rule(case_user_f%d(), %s, [%s]).\n", counter, head, body));
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
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

    public static boolean isStrRule(String s) {
        return s.startsWith("r_str_");
    }

    static boolean isAss(String s) {
        return s.equals("ass") || s.equals("abducible");
    }

    static boolean isPreference(String r) {
        return r.startsWith("p") || r.startsWith("ass(neg(prefer(");
    }

    static String getHead(String name, List<String> args) {
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
            return TECH + ".pl";
        } else if (r.startsWith("r_op_") || (isPreference(r) && r.endsWith("op"))) {
            return OP + ".pl";
        } else if (r.startsWith("r_str_") || isPreference(r)) {
            return STR + ".pl";
        } else if (r.startsWith(CASE_USER_F) || r.startsWith(P_USER_)) {
            return USER_EVIDENCE_FILENAME;
        } else if (r.startsWith("case")) {
            return "evidence.pl";
        } else if (r.startsWith("bg")) {
            return "backgroundgorgias_renumbered.pl";
        } else {
            System.err.println(r + " which file?");
            return "";
        }
    }

    private static String getAllPreds() {
        BufferedReader br;
        Set<String> preds = new HashSet<>();
        String[] files = new String[] {TECH + ".pl", OP + ".pl", STR + ".pl", "backgroundgorgias_renumbered.pl"};
        try {
            for (String f : files) {
                br = new BufferedReader(new FileReader(f));
                br.lines().forEach(line -> {
                    line = line.split("%")[0];
                    if (line.startsWith("rule(") && line.contains("[")) {
                        String[] body = getBodyOfLine(line);
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

    private static String[] getBodyOfLine(String line) {
        return line.split("\\[")[1].split("\\]")[0].split("\\)");
    }

    static String getHeadOfLine(String line) {
        return line.split("\\)")[1].replaceFirst(",", "") + ")";
    }

    static String getRuleFromFile(String rulename, int file) {
        String filename;
        switch(file) {
            case 0:
                filename = TECH + ".pl";
                break;
            case 1:
                filename = OP + ".pl";
                break;
            case 2:
                filename = STR + ".pl";
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

    public static void main(String[] args) {

//        String[] preds = new String[] {"industry(T)","targetCountry(X,Att)","fileChara(Filename,MD5,Size,CompileTime,Desc,Filetype,C1)","poorRelation(C,T)","noPriorHistory(X)","infraUsed(Infra,Att)","hasResources(X)","majorityIpOrigin(X,Att)","stolenValidSignedCertificates(Att)","cybersuperpower(X)","espionage,doxing)","attackPeriod(Att,[Year,Month])","governmentLinked(P,C)","domainRegisteredDetails(Server,Name,Addr)","ipResolution(S,IP,D)","infectionMethod(usb,M)","attackOrigin(X,Att)","highLevelSkill(Att)","usesZeroDayVulnerabilities(M)","hasPoliticalMotive(C,T,Date2)","malwareUsedInAttack(M,Att)","news(News,T,Date2)","prominentGroup(X)","attackPossibleOrigin(X,Att)","notForBlackMarketUse(M)","similarCCServer(M1,M2)","publicCommentsRelatedToGov(P,C)","zeroday,customMalware)","gci_tier(X,leading)","torIP(IP)","malwareLinkedTo(M2,X)","sysLanguage(L,Att)","clientSideExploits)","eternalBlue)","spoofedIP(IP)","ipGeoloc(X,IP)","addressType(Addr,Type)","sophisticatedMalware(M)","identifiedIndividualInAttack(P,Att)","goodRelation(X,Y)","industry(Ind,X)","cyberespionage)","languageInCode(L,Att)","groupOrigin(Group,C)","hasCapability(X,Att)","isInfrastructure(Ind)","infraRegisteredIn(X,Infra)","informationRich(Ind)","hasResources(X)","fileCharaMalware(C2,M2)","claimedResponsibility(X,Att)","addrInCountry(Addr,X)","similarFileChara(C1,C2)","dateApplicable(Date1,Date2)","attackSourceIP(IP,M)","hijackCorporateClouds(Att)","highVolumeAttack(Att)","imposedSanctions(T,C,Date)","causeOfConflict(X,T,News)","ccServer(S,M)","specificConfigInMalware(M)","cyberespionage,undergroundBusiness)","specificTarget(Att)","simlarCodeObfuscation(M1,M2)","requireHighResource(Att)","target(X,Att)","hasMotive(X,Att)","similar(M1,M2)","hasEconomicMotive(C,T)","longDurationAttack(Att)","sharedCode(M1,M2)","commandAndControlEasilyFingerprinted(M)","highSecurity(T)","firstLanguage(L,X)","geolocatedInGovFacility(P,C)","country(X)","malwareModifiedFrom(M1,M2)","gci_tier(X,initiating)","gci_tier(X,maturing)","isCulprit(Group,Att)"};
//        Set<String> set = new HashSet<>();
//        for (String pred : preds) {
//            int size = set.size();
//            set.add(pred.split("\\(")[0]);
//            if (set.size() == size) {
//                System.out.println(pred);
//            }
//        }
//        System.out.println(set);
//        System.out.println(set.size());
    }
}
