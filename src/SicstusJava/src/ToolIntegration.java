import javafx.util.Pair;

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
    static final String TOR_IP_FILE = "tor_ip_list.pl";

    static final String VIRUS_TOTAL_PROLOG_FILE = "virustotal/virustotal.pl";
    static final String virusTotalLogFileTemplate = "virustotal/virustotal_report_";


    static final String SQUID_LOG_RULES_PL = "squid_log_rules.pl";
    static final String AUTOMATED_GEOLOCATION_PL = "automated_geolocation.pl";

    static final String CASE_OSSEC_LOG_ = "case_ossec_log_malware_";
    static final String CASE_SQUID_LOG = "case_squid_log_";
    static final String RULE_CASE_SQUID_LOG = "rule(" + CASE_SQUID_LOG + "%d(), squid_log(%s,%s,'%s',%s),[]).\n";
    static final String RULE_CASE_SQUID_LOG1 = "\nrule(" + CASE_SQUID_LOG + "1_%d(), ip(%s),[]).\n";
    static final String CASE_TOR_CHECK = "case_torCheck";
    static final String RULE_CASE_TOR_CHECK = "rule(" + CASE_TOR_CHECK + "%d(), %s, []).\n";
    static final String RULE_CASE_TOR_CHECK1 = "rule(" + CASE_TOR_CHECK + "1_%d(), ip(%s), []).\n";
    static final String CASE_AUTOGEN_GEOLOCATION = "case_autogen_geolocation_";
    static final String RULE_CASE_AUTOGEN_GEOLOCATION = "rule(" + CASE_AUTOGEN_GEOLOCATION + "%d(), ipGeoloc(%s,%s), []).\n";

    private List<String> virustotalFinishedScanningIP;
    private int torCount = 0;
    private int virustotalCount = 0;
    private int ossecCount = 0;

    public ToolIntegration() {
        Utils.clearFile(VIRUS_TOTAL_PROLOG_FILE);
        virustotalFinishedScanningIP = new ArrayList<>();
    }

    private String parseOSSEC(String filename, String attackname) {
        final String[] s = new String[1];
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));

            final String RULE_TEMPLATE = "rule(%s%d(), %s,[]).";
            final String RULE = "Rule:";
            final String LEVEL = "(level";
            final String INFECTED_MSG_PREFIX = "Infected machine with";
            final String SSHD_LOG_PREFIX = "sshd[";
            boolean isBruteForce = false;

            String line = br.readLine();

            while (line != null) {
                if (line.startsWith(RULE)) {
//                    int ruleIndex = Integer.parseInt(
//                            line.substring(line.indexOf(RULE) + RULE.length(),
//                                    line.indexOf("fired")).replace(" ", ""));
//
//                    int level = Integer.parseInt(
//                            line.substring(line.indexOf(LEVEL) + LEVEL.length(),
//                                    line.indexOf(')')).replace(" ", ""));

                    String msg = line.substring(line.indexOf('"') + 1, line.lastIndexOf('"'));

                    if (msg.startsWith(INFECTED_MSG_PREFIX)) {
                        String malwareName = msg.substring(msg.indexOf(INFECTED_MSG_PREFIX)
                                + INFECTED_MSG_PREFIX.length())
                                .replace(" ", "")
                                .replace("'", "");
                        String fact = String.format("malwareUsedInAttack('%s',%s)", malwareName, attackname);
                        s[0] = String.format(RULE_TEMPLATE, CASE_OSSEC_LOG_, ossecCount, fact);
                        ossecCount++;
                        break;
                    } else if (msg.startsWith("SSHD brute force")) {
                        isBruteForce = true;
                    }
                } else if (isBruteForce && line.startsWith(SSHD_LOG_PREFIX)) {
                    String IPADDRESS_PATTERN =
                            "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";

                    Pattern pattern = Pattern.compile(IPADDRESS_PATTERN);
                    Matcher matcher = pattern.matcher(line);
                    if (matcher.find()) {
                        String ipString = matcher.group();
                        String ipProlog = "[" + ipString.replace(".", ",") + "]";
                        System.out.println(ipString + "   " + ipProlog);
                        String fact = String.format("attackSourceIP(%s, %s)", ipProlog, attackname);
                        s[0] = String.format(RULE_TEMPLATE, CASE_OSSEC_LOG_, ossecCount, fact);
                        ossecCount++;
                        break;
                    }
                }
                line = br.readLine();
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return s[0];
    }

    /*
        * User upload HIDS notification (SQUID format)
        * Filter for keyword: TCP_DENIED/407, TCP_MISS/404
        *
        * Extract: IP, port, code, unixTimestamp
        * */
    private static String parseSquidLog(String line, int count, String malware) {
        String[] ss = line.split(" ");
        String resultCode = ss[3];
        String forwardedAddr = ss[6];
        String[] ip = forwardedAddr.split(":")[0].split("\\.");
        if (ip.length == 4) {
            String port = forwardedAddr.split(":")[1];
            String ipString = String.format("[%s,%s,%s,%s]", ip[0], ip[1], ip[2], ip[3]);
            return String.format(RULE_CASE_SQUID_LOG + RULE_CASE_SQUID_LOG1,
                    count, ipString, port, resultCode, malware, count, ipString);
        } else {
            System.out.println(forwardedAddr + " is not valid IP");
        }
        return "";
    }

    public static void parseSquidLogFile(File file, String malware) {
        try {
            System.out.println("Processing squid log: " + file);
            BufferedReader br = new BufferedReader(new FileReader(file));
            StringBuilder sb = new StringBuilder();
            final int[] c = {0};
            br.lines().forEach(x -> {
                sb.append(parseSquidLog(x, c[0], malware) + "\n");
                c[0]++;
            });

            FileWriter w = new FileWriter(SQUID_LOG_RULES_PL, true);
//            w.write(":- multifile rule/3.\n");
            w.write(sb.toString());
            w.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    void torIntegration() {
        if (torCount == 0) {
            Utils.clearFile(TOR_IP_FILE);
        }

        Set<String[]> ips = getTargetServerIP(Utils.EVIDENCE_FILENAME);
        ips.addAll(getTargetServerIP(Utils.USER_EVIDENCE_FILENAME));

        System.out.println(ips.size() + " server IPs found!");

        for (String[] ip : ips) {
            String ipPredString = String.format("[%s,%s,%s,%s]", ip[0], ip[1], ip[2], ip[3]);
            String ipString = String.format("%s.%s.%s.%s", ip[0], ip[1], ip[2], ip[3]);
            processTorCheckFile(getTorFile(ipString), ipPredString);
        }
    }

    private static Stream<String> getTorFile(String ipString) {
        String domainName = String.format("https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=%s&port=", ipString);
        String command = "curl " + domainName;
        return executeUNIXCommand(command);

    }

    private static String virustotalScanFile(File file) {
        String resource = ScanFile.getFileResource(file);
        return GetFileScanReport.getFileScanReport(resource).getScans().toString();
//        String filename = file.getAbsolutePath();
//        String filename = "/Users/linna/Downloads/2015-08-31-traffic-analysis-exercise.pcap";
//        String command = String.format("curl -v -F 'file=@/%s' -F apikey=%s https://www.virustotal.com/vtapi/v2/file/scan", filename, ApiDetails.API_KEY);
//        return executeUNIXCommand(command);
//        return scanInfo.getResource();
    }

    static Set<String[]> getTargetServerIP(String filename) {
        Set<String[]> ips = new HashSet<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            br.lines().forEach(line -> {
                if (line.contains(targetServerIPPredicate)) {
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
            final int[] count = {torCount};
            final StringBuilder sb = new StringBuilder("\n");
            lines.forEach(line -> {
                if (!line.startsWith("#") && !line.startsWith("<!")) {
                    String[] ipStrings = line.split("\\.");
                    String ipString = String.format("[%s,%s,%s,%s]", ipStrings[0], ipStrings[1], ipStrings[2], ipStrings[3]);
                    String fact = String.format("torIP(%s, %s)", ipString, serverIP);
                    sb.append(String.format(RULE_CASE_TOR_CHECK, count[0], fact));
                    sb.append(String.format(RULE_CASE_TOR_CHECK1, count[0], ipString));
                    count[0]++;
                }
            });
            torCount = count[0];
            Files.write(Paths.get(TOR_IP_FILE), sb.toString().getBytes(), StandardOpenOption.APPEND);

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
                    return convertToAtom(reply[3]);
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
        File virusTotalReportFile = new File(virusTotalLogFileTemplate + ip);
        if (!virustotalFinishedScanningIP.contains(ip)) {
//            GetIPAddressReport.getIPAddressReport(ip, virusTotalLogFileTemplate);
            List<Pair<Pair<Integer, Integer>, String>> res = GetIPAddressReport.getIPResolution(ip);
            if (res != null) {
                processVirusTotalFile(res, ip, year, month);
                virustotalFinishedScanningIP.add(ip);
            }
        } else {
            System.out.println(virusTotalReportFile + " already exists.");
        }
    }

    public static Comparator<Pair<Pair<Integer, Integer>, String>> PairComparator
            = new Comparator<Pair<Pair<Integer, Integer>, String>>() {
        @Override
        public int compare(Pair<Pair<Integer, Integer>, String> o1, Pair<Pair<Integer, Integer>, String> o2) {
            int keykeyCompare = o1.getKey().getKey().compareTo(o2.getKey().getKey());
            if (keykeyCompare == 0) {
                int keyvalueCompare = o1.getKey().getValue().compareTo(o2.getKey().getValue());
                if (keyvalueCompare == 0) {
                    return o1.getValue().compareTo(o2.getValue());
                } else {
                    return keyvalueCompare;
                }
            } else {
                return keykeyCompare;
            }
        }
    };

    void processVirusTotalFile(List<Pair<Pair<Integer, Integer>, String>> res, String ip, int year, int month) {
        try {
            FileWriter w = new FileWriter(VIRUS_TOTAL_PROLOG_FILE, true);
            Collections.sort(res, PairComparator);
            int prevYear = -1;
            int prevMonth = -1;
            for (int i = 0; i < res.size(); i++) {
                Pair<Pair<Integer, Integer>, String> r = res.get(i);
                String[] ips = ip.split("\\.");
                String ipString = String.format("[%s,%s,%s,%s]", ips[0], ips[1], ips[2], ips[3]);
                String hostname = r.getValue();
                Pair<Integer, Integer> datePair = r.getKey();
//                String[] d = dateString.split(" ")[0].split("-");
                String resolvedDate = String.format("[%d,%d]", datePair.getKey(), datePair.getValue());

                int currYear = datePair.getKey();
                int currMonth = datePair.getValue();

                if (dateExceeded(year, month, currYear, currMonth)) {
                    break;
                }

                if (!dateNotReached(year, month, prevYear, prevMonth)) {
                    String fact = String.format("ipResolution('%s',%s,%s)", hostname, ipString, resolvedDate);
                    w.write(String.format("rule(case_virustotal_res%d(), %s, []).\n", virustotalCount, fact));
                    virustotalCount++;
                    prevYear = currYear;
                    prevMonth = currMonth;
                }
            }
            w.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // returns true if year/month is before prevYear/prevMonth
    private boolean dateNotReached(int year, int month, int prevYear, int prevMonth) {
        return (year < prevYear) || (year == prevYear && month < prevMonth);
    }

    // returns true is year/month is after currYear/currMonth
    private boolean dateExceeded(int year, int month, int currYear, int currMonth) {
        return year > currYear || (year == currYear && month > currMonth);
    }

    static void processVirusTotalFile(String filename, String ip) {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            FileWriter w = new FileWriter(VIRUS_TOTAL_PROLOG_FILE, true);
            String line = br.readLine();

            StringJoiner sj = new StringJoiner(",");
            for (String s : ip.split("\\.")) {
                sj.add(s);
            }
            
            int count = 0;
            String server = null;
            String ipStrings = "[" + sj + "]";
            String date = null;
            boolean done = false;
            while (line != null) {
                if (line.startsWith("Host Name :")) {
                    server = "'" + line.split(" : ")[1] + "'";
                } else if (line.startsWith("Last Resolved :")) {
                    String s = line.split(" : ")[1];
                    String[] d = s.split(" ")[0].split("-");
                    date = String.format("[%d,%d]", Integer.parseInt(d[0]), Integer.parseInt(d[1]));
                    done = true;
                }

                if (done) {
                    String fact = String.format("ipResolution(%s,%s,%s)",
                            server, ipStrings, date);
                    w.write(String.format("rule(case_virustotal_res%d(), %s, []).\n", count, fact));
                    count++;
                }
                line = br.readLine();
            }
            w.close();
            br.close();

        } catch (FileNotFoundException e) {
            System.err.println(filename + " not found (processVirusTotalFile)");
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
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
//        Set<String> ips = new HashSet<>();
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
            FileWriter f_w = new FileWriter(AUTOMATED_GEOLOCATION_PL, true);
            int c = 0;
            for (Pair<String, String> ipDate : ipDates) {
                String ip = ipDate.getKey();
                String ipString = convertPrologIPToString(ip);
                String country = ipGeolocation(ipString);
                String rule = String.format(RULE_CASE_AUTOGEN_GEOLOCATION, c, country, ip);
                c++;
                f_w.write(rule);

                String date = ipDate.getValue();
                if (!ip.equals(date)) {
                    String[] s = date.substring(1, date.length() - 1).split(",");
                    int year = Integer.parseInt(s[0]);
                    int month = Integer.parseInt(s[1]);
                    getVirustotalReportAndProcess(ipString, year, month);
                }
            }
            f_w.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // suspicious process -
    // filters ossec alerts given level and msg
    public boolean possibleAttack(int level, String msg) {
        if (level < 9) {
            return false;
        } else if (level == 12) {
            return true;
        }
        final String[] keywords = new String[]{"deny", "failure", "failed", "bad",
                "invalid", "error", "brute force", "multiple", "high amount",
                "breakin", "infected", "malware", "worm", "trojan", "virus", "suspicious"};
        String msgLower = msg.toLowerCase();
        for (String keyword : keywords) {
            if (msgLower.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    // returns unix timestamp
    public int getTimestamp() {
        return -1;
    }

    public static boolean relevantLog(int level, String msg) {
        if (level >= 3) {
            return false;
        }
        final String[] keywords = new String[]{"bad", "invalid", "error",
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
    public static List<String> parseSnortLogs(String filename) {
        final String PRIORITY = "[Priority: ";
        List<String> prologPreds = new ArrayList<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            StringBuilder sb = new StringBuilder();
            br.lines().forEach(x -> sb.append(x));
            String allLines = sb.toString();
            String[] logs = allLines.split("\\[\\*\\*\\] \\[[0-9]");
            for (String log : logs) {
                if (log.length() > 0) {
                    int priorityStart = log.indexOf(PRIORITY) + PRIORITY.length();
                    int priority = Integer.parseInt(log.substring(priorityStart, log.indexOf("]", priorityStart)));
                    String msg = log.substring(0, log.indexOf("[**]"));
                    if (relevantLog(priority, msg)) {
                        final int IP_SEPARATOR_POS = log.indexOf("->");
                        String srcIP = parseIPFromString(log.substring(log.indexOf("]"), IP_SEPARATOR_POS));
                        String destIP = parseIPFromString(log.substring(IP_SEPARATOR_POS));
                        System.out.println("SRC: " + srcIP + " DEST: " + destIP + " MSG: " + msg);
                    }
                }
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return prologPreds;
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
//        System.out.println("RESOURCE: " + virustotalScanFile(new File("/Users/linna/Downloads/2015-08-31-traffic-analysis-exercise.pcap")));
//        ToolIntegration ti = new ToolIntegration();
//        ti.torIntegration();
//        preprocessFiles();
//        getVirustotalReportAndProcess("74.125.224.72");
//        System.out.println(ti.parseOSSEC("ossec_alert1.log", "saysomething"));\
        parseSnortLogs("/Users/linna/Downloads/tg_snort_full/alert.full");
    }
}
