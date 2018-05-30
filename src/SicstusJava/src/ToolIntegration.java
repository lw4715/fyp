//import javafx.util.Pair;
import com.sun.tools.javac.util.Pair;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;


public class ToolIntegration {
    static final String targetServerIPPredicate = "targetServerIP";
    static final String TOR_IP_FILE = "toolIntegration/tor_ip_list.pl";

    static final String VIRUS_TOTAL_PROLOG_FILE = "toolIntegration/virustotal.pl";
    static final String virusTotalLogFileTemplate = "toolIntegration/virustotal_report_";


//    private static final String SQUID_LOG_RULES_PL = "toolIntegration/squid_log_rules.pl";
    static final String AUTOMATED_GEOLOCATION_PL = "toolIntegration/automated_geolocation.pl";

//    static final String CASE_OSSEC_LOG_ = "case_ossec_log_malware_";
//    static final String CASE_SQUID_LOG = "case_squid_log_";
//    static final String RULE_CASE_SQUID_LOG = "rule(" + CASE_SQUID_LOG + "%d(), squid_log(%s,%s,'%s',%s),[]).\n";
//    static final String RULE_CASE_SQUID_LOG1 = "\nrule(" + CASE_SQUID_LOG + "1_%d(), ip(%s),[]).\n";

    static final String CASE_TOR_CHECK = "case_torCheck";
    static final String RULE_CASE_TOR_CHECK = "rule(" + ToolIntegration.CASE_TOR_CHECK + "%d(), %s, []).\n";
    static final String RULE_CASE_TOR_CHECK1 = "rule(" + ToolIntegration.CASE_TOR_CHECK + "1_%d(), ip(%s), []).\n";
    static final String CASE_AUTOGEN_GEOLOCATION = "case_autogen_geolocation_";
    static Set<String> geolocatedIPs;

    static final String RULE_CASE_AUTOGEN_GEOLOCATION = "rule(" + ToolIntegration.CASE_AUTOGEN_GEOLOCATION + "%d(), ipGeoloc(%s,%s), []).\n";
    static final String RULE_CASE_VIRUSTOTAL_RES = "case_virustotal_res";
    static final String RULE_CASE_VIRUSTOTAL_RES_TEMPLATE = "rule(" + ToolIntegration.RULE_CASE_VIRUSTOTAL_RES + "%d(), %s, []).";

    private final List<String> virustotalFinishedScanningIP;
    private final String IPADDRESS_PATTERN =
            "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
    private int virustotalCount;
    private int torCount;
//    private int ossecCount;
    private int geolocCount;

    public ToolIntegration() {
        this.virustotalFinishedScanningIP = new ArrayList<>();
        ToolIntegration.geolocatedIPs = new HashSet<>();
    }

//    private String parseOSSEC(String filename, String attackname) {
//        String[] s = new String[1];
//        try {
//            BufferedReader br = new BufferedReader(new FileReader(filename));
//
//            String RULE_TEMPLATE = "rule(%s%d(), %s,[]).";
//            String RULE = "Rule:";
//            String LEVEL = "(level";
//            String INFECTED_MSG_PREFIX = "Infected machine with";
//            String SSHD_LOG_PREFIX = "sshd[";
//            boolean isBruteForce = false;
//
//            String line = br.readLine();
//
//            while (line != null) {
//                if (line.startsWith(RULE)) {
//
//                    String msg = line.substring(line.indexOf('"') + 1, line.lastIndexOf('"'));
//
//                    if (msg.startsWith(INFECTED_MSG_PREFIX)) {
//                        String malwareName = msg.substring(msg.indexOf(INFECTED_MSG_PREFIX)
//                                + INFECTED_MSG_PREFIX.length())
//                                .replace(" ", "")
//                                .replace("'", "");
//                        String fact = String.format("malwareUsedInAttack('%s',%s)", malwareName, attackname);
//                        s[0] = String.format(RULE_TEMPLATE, ToolIntegration.CASE_OSSEC_LOG_, this.ossecCount, fact);
//                        this.ossecCount++;
//                        break;
//                    } else if (msg.startsWith("SSHD brute force")) {
//                        isBruteForce = true;
//                    }
//                } else if (isBruteForce && line.startsWith(SSHD_LOG_PREFIX)) {
//                    Pattern pattern = Pattern.compile(this.IPADDRESS_PATTERN);
//                    Matcher matcher = pattern.matcher(line);
//                    if (matcher.find()) {
//                        String ipString = matcher.group();
//                        String ipProlog = "[" + ipString.replace(".", ",") + "]";
//                        String fact = String.format("attackSourceIP(%s, %s)", ipProlog, attackname);
//                        s[0] = String.format(RULE_TEMPLATE, ToolIntegration.CASE_OSSEC_LOG_, this.ossecCount, fact);
//                        this.ossecCount++;
//                        break;
//                    }
//                }
//                line = br.readLine();
//            }
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        return s[0];
//    }


    void torIntegration() {
        if (this.torCount == 0) {
            Utils.clearFile(ToolIntegration.TOR_IP_FILE);
        }

        Set<String[]> ips = ToolIntegration.getTargetServerIP(Utils.EVIDENCE_PL);
        ips.addAll(ToolIntegration.getTargetServerIP(Utils.USER_EVIDENCE_FILENAME));

        System.out.println("Tor: " + ips.size());

        for (String[] ip : ips) {
            String ipPredString = String.format("[%s,%s,%s,%s]", ip[0], ip[1], ip[2], ip[3]);
            String ipString = String.format("%s.%s.%s.%s", ip[0], ip[1], ip[2], ip[3]);
            this.processTorCheckFile(ToolIntegration.getTorFile(ipString), ipPredString);
        }
    }

    private static Stream<String> getTorFile(String ipString) {
        String domainName = String.format("https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=%s&port=", ipString);
        String command = "curl " + domainName;
        return ToolIntegration.executeUNIXCommand(command);

    }

    static Set<String[]> getTargetServerIP(String filename) {
        Set<String[]> ips = new HashSet<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            br.lines().forEach(line -> {
                if (line.contains(ToolIntegration.targetServerIPPredicate)) {
                    String head = Utils.getHeadOfLine(line);
                    String[] ip = head.split("\\]")[0].split("\\[")[1].split(",");
                    ips.add(ip);
                }
            });
        } catch (Exception e) {

        }
        return ips;
    }

//      use imperial ip as example, write result in evidence
    void processTorCheckFile(Stream<String> lines, String serverIP) {
        try {
            int[] count = {this.torCount};
            StringBuilder sb = new StringBuilder("\n");
            lines.forEach(line -> {
                if (!line.startsWith("#") && !line.startsWith("<!")) {
                    String[] ipStrings = line.split("\\.");
                    String ipString = String.format("[%s,%s,%s,%s]", ipStrings[0], ipStrings[1], ipStrings[2], ipStrings[3]);
                    String fact = String.format("torIP(%s, %s)", ipString, serverIP);
                    sb.append(String.format(ToolIntegration.RULE_CASE_TOR_CHECK, count[0], fact));
                    sb.append(String.format(ToolIntegration.RULE_CASE_TOR_CHECK1, count[0], ipString));
                    count[0]++;
                }
            });
            this.torCount = count[0];
            Files.write(Paths.get(ToolIntegration.TOR_IP_FILE), sb.toString().getBytes(), StandardOpenOption.APPEND);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // convert [a,b,c,d] to a.b.c.d
    static String convertPrologIPToString(String ip) {
        return ip.substring(ip.indexOf('[') + 1, ip.lastIndexOf(']')).replace(",", ".").replace(" ", "");
    }

    // make automatic
    // adapted from https://about.ip2c.org/#examplejava
    static String ipGeolocation(String ip) {
        HttpURLConnection urlcon = null;
        try {
            urlcon = (HttpURLConnection)new URL("http://ip2c.org/"+ip).openConnection();
        } catch (IOException e) {
            e.printStackTrace();
        }
        urlcon.setDefaultUseCaches(false);
        urlcon.setUseCaches(false);
        try {
            urlcon.connect();
            InputStream is = urlcon.getInputStream();
            int c;
            String s = "";
            while((c = is.read()) != -1) s+= (char)c;
            is.close();
            switch(s.charAt(0))
            {
                case '0':
                    System.err.println("Something wrong");
                    break;
                case '1':
                    String[] reply = s.split(";");
                    return ToolIntegration.convertToAtom(reply[3]);
                case '2':
                    System.err.println("Not found in database");
                    break;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String convertToAtom(String s) {
        return s.toLowerCase().replace(" ", "_");
    }

    void getVirustotalReportAndProcess(String ip, Integer year, Integer month) {
        System.out.println("Processing " + ip + " : " + year + "," + month);
        File virusTotalReportFile = new File(ToolIntegration.virusTotalLogFileTemplate + ip);
        if (!this.virustotalFinishedScanningIP.contains(ip)) {
            List<Pair<Pair<Integer, Integer>, String>> res = GetIPAddressReport.getIPResolution(ip);
            if (res != null) {
                this.processVirusTotalFile(res, ip, year, month);
                this.virustotalFinishedScanningIP.add(ip);
            }
        } else {
            System.out.println(virusTotalReportFile + " already exists.");
        }
    }

    public static Comparator<Pair<Pair<Integer, Integer>, String>> PairComparator
            = (o1, o2) -> {
                int keykeyCompare = o1.fst.fst.compareTo(o2.fst.fst);
                if (keykeyCompare == 0) {
                    int keyvalueCompare = o1.fst.snd.compareTo(o2.fst.snd);
                    if (keyvalueCompare == 0) {
                        return o1.snd.compareTo(o2.snd);
                    } else {
                        return keyvalueCompare;
                    }
                } else {
                    return keykeyCompare;
                }
            };

    void processVirusTotalFile(List<Pair<Pair<Integer, Integer>, String>> res, String ip, int year, int month) {
        try {
            FileWriter w = new FileWriter(ToolIntegration.VIRUS_TOTAL_PROLOG_FILE, true);
            Collections.sort(res, ToolIntegration.PairComparator);
            int prevYear = -1;
            int prevMonth = -1;
            for (int i = 0; i < res.size(); i++) {
                Pair<Pair<Integer, Integer>, String> r = res.get(i);
                String[] ips = ip.split("\\.");
                String ipString = String.format("[%s,%s,%s,%s]", ips[0], ips[1], ips[2], ips[3]);
                String hostname = r.snd;
                Pair<Integer, Integer> datePair = r.fst;
                String resolvedDate = String.format("[%d,%d]", datePair.fst, datePair.snd);

                int currYear = datePair.fst;
                int currMonth = datePair.snd;

                if (this.dateExceeded(year, month, prevYear, prevMonth) && !this.dateExceeded(year, month, currYear, currMonth)) {
                    String fact = String.format("ipResolution('%s',%s,%s)", hostname, ipString, resolvedDate);
                    w.write(String.format(ToolIntegration.RULE_CASE_VIRUSTOTAL_RES_TEMPLATE + "\n", this.virustotalCount, fact));
                    this.virustotalCount++;
                    break;
                }
                prevYear = currYear;
                prevMonth = currMonth;

            }
            w.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // returns true is year /month is after currYear/currMonth
    private boolean dateExceeded(int year, int month, int currYear, int currMonth) {
        return year > currYear || year == currYear && month > currMonth;
    }


    private static Stream<String> executeUNIXCommand(String command) {
        Process p;
        try {
            p = Runtime.getRuntime().exec(command);
            p.waitFor();
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(p.getInputStream()));

            return reader.lines();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // automated geolocation of ip addresses, resolution
    void preprocessFiles(List<String> allFiles) {
        System.out.println("Tool integration...");
        Set<Pair<String, String>> ipDates = new HashSet<>();
        for (String f : allFiles) {
            try {
                BufferedReader br = new BufferedReader(new FileReader(f));

                br.lines().forEach(line -> {
                    if (line.split("%")[0].contains("ip([")) {
                        String head = Utils.getHeadOfLine(line);
                        String ip = head.substring(head.indexOf('['), head.indexOf(']') + 1);
                        String date = head.substring(head.lastIndexOf('['), head.lastIndexOf(']') + 1);
                        ipDates.add(new Pair<>(ip, date));
                    }
                });
                br.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        try {
            FileWriter f_w = new FileWriter(ToolIntegration.AUTOMATED_GEOLOCATION_PL, true);
            for (Pair<String, String> ipDate : ipDates) {
                String ip = ipDate.fst;
                String ipString = ToolIntegration.convertPrologIPToString(ip);

                if (!ToolIntegration.geolocatedIPs.contains(ipString)) {
                    String country = ToolIntegration.ipGeolocation(ipString);
                    ToolIntegration.geolocatedIPs.add(ipString);
                    String rule = String.format(ToolIntegration.RULE_CASE_AUTOGEN_GEOLOCATION, this.geolocCount, country, ip);
                    this.geolocCount++;
                    f_w.write(rule);
                }

                String date = ipDate.snd;
                if (!ip.equals(date)) {
                    System.out.println("Virustotal " + ip + " " + date);
                    String[] s = date.substring(1, date.length() - 1).split(",");
                    int year = Integer.parseInt(s[0]);
                    int month = Integer.parseInt(s[1]);
                    this.getVirustotalReportAndProcess(ipString, year, month);
                }
            }
            f_w.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean relevantLog(int level, String msg) {
        if (level >= 3) {
            return false;
        }
        String[] keywords = {"bad", "invalid", "error",
                "brute force", "multiple", "high amount", "breakin", "infected",
                "malware", "worm", "trojan", "virus", "denial of service", "malicious"};
        String msgLower = msg.toLowerCase();
        for (String keyword : keywords) {
            if (msgLower.contains(keyword)) {
                return true;
            }
        }
        return false;
    }




    // return prolog rules
    public static Map<String, Map<String, Map<String, Integer>>> parseSnortLogs(File file) {
        String PRIORITY = "[Priority: ";
        List<String> prologPreds = new ArrayList<>();
        // key: srcIP value: (key: destIP value: set(msg, times occurred))
        Map<String, Map<String, Map<String, Integer>>> srcIPMap = new HashMap<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(file));
            StringBuilder sb = new StringBuilder();
            br.lines().forEach(x -> sb.append(x));
            String allLines = sb.toString();
            String[] logs = allLines.split("\\[\\*\\*\\] \\[[0-9]");
            for (String log : logs) {
                if (log.length() > 0) {
                    int priorityStart = log.indexOf(PRIORITY) + PRIORITY.length();
                    int priority = Integer.parseInt(log.substring(priorityStart, log.indexOf("]", priorityStart)));
                    String msg = log.substring(log.indexOf("]") + 1, log.indexOf("[**]"));
                    if (ToolIntegration.relevantLog(priority, msg)) {
                        int IP_SEPARATOR_POS = log.indexOf("->");
                        String srcIP = ToolIntegration.parseIPFromString(log.substring(log.indexOf("]"), IP_SEPARATOR_POS));
                        String destIP = ToolIntegration.parseIPFromString(log.substring(IP_SEPARATOR_POS));
                        if (ToolIntegration.isUsefulIP(srcIP) && ToolIntegration.isUsefulIP(destIP)) {
                            Map<String, Map<String, Integer>> m;
                            if (srcIPMap.get(srcIP) == null) {
                                m = new HashMap<>();
                                srcIPMap.put(srcIP, m);
                            }
                            m = srcIPMap.get(srcIP);
                            Map<String, Integer> msgs;
                            if (m.get(destIP) == null) {
                                msgs = new HashMap<>();
                                m.put(destIP, msgs);
                            }
                            msgs = m.get(destIP);
                            if (msgs.get(msg) == null) {
                                msgs.put(msg, 0);
                            }
                            msgs.put(msg, msgs.get(msg) + 1);
                        }
                    }
                }
            }
            Map<String, Map<String, Map<String, Integer>>> filteredMap = new HashMap<>();
            List<Integer> list = new ArrayList<>();

            for (String srcIP : srcIPMap.keySet()) {
                int size = ToolIntegration.recursiveSizeOfMap(srcIPMap.get(srcIP));
                if (list.size() <= 5) {
                    list.add(size);
                    Collections.sort(list);
                } else if (size > list.get(0)) {
                    list.remove(0);
                    list.add(size);
                    Collections.sort(list);
                }
            }

            for (String srcIP : srcIPMap.keySet()) {
                if (ToolIntegration.recursiveSizeOfMap(srcIPMap.get(srcIP)) > list.get(0)) {
                    filteredMap.put(srcIP, srcIPMap.get(srcIP));
                }
            }
            return filteredMap;

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    // return fullsize of map
    private static int recursiveSizeOfMap(Map<String, Map<String, Integer>> m) {
        int acc = 0;
        for (Map<String, Integer> n : m.values()) {
            for (Integer i : n.values()) {
                acc += i;
            }
        }
        return acc;
    }

    private static boolean isUsefulIP(String ip) {
        return !(ip.equals("0.0.0.0") || ip.equals("255.255.255.255"));
    }

    private static String parseIPFromString(String str) {
        String IPADDRESS_PATTERN =
                "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";

        Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
        Matcher matcher = pattern.matcher(str);
        if (matcher.find()) {
            return matcher.group();
        }
        return null;
    }

    public static void main(String[] args) {
            Map<String, String> m = new HashMap();
        m.put("key", "val");
        m.put("key1", "val1");
        System.out.println(m);
    }

}
