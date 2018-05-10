
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.stream.Stream;


public class ToolIntegration {
    static final String targetServerIPPredicate = "targetServerIP";
    static final String torIPFile = "torCheckIPList";
    static final String virusTotalPrologFileTemplate = "virustotal_";
    static final String virusTotalLogFileTemplate = "virustotal_res_";
    static final String SQUID_LOG_RULES_PL = "squid_log_rules.pl";
    static final List<String> virusTotalFiles = new ArrayList<>();

    private int torCount = 0;

    /*
        * User upload HIDS notification (OSSEC format)
        * Filter for keyword: TCP_DENIED/407, TCP_MISS/404
        * Repeated access to same extension (last in html) e.g. "xxx3.php"
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
            return String.format("rule(case_squid_log_%d, squid_log(%s,%s,'%s',%s),[]).",
                    count, ipString, port, resultCode, malware);
        } else {
            System.out.println(forwardedAddr + " is not valid IP");
        }
        return "";
    }

    public static void parseSquidLogFile(String filename, String malware) {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            StringBuilder sb = new StringBuilder();
            final int[] c = {0};
            br.lines().forEach(x -> {
                sb.append(ToolIntegration.parseSquidLog(x, c[0], malware) + "\n");
                c[0]++;
            });

            FileWriter w = new FileWriter(SQUID_LOG_RULES_PL);
            w.write(":- multifile rule/3.\n");
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
            Utils.clearFile(torIPFile + ".pl");
        }

        Set<String[]> ips = getTargetServerIP(Utils.EVIDENCE_FILENAME);
        ips.addAll(getTargetServerIP(Utils.USER_EVIDENCE_FILENAME));

        System.out.println(ips.size() + " server IPs found!");
        for (String[] ip : ips) {
            String ipPredString = String.format("[%s,%s,%s,%s]", ip[0], ip[1], ip[2], ip[3]);
            String ipString = String.format("%s.%s.%s.%s", ip[0], ip[1], ip[2], ip[3]);
//            System.out.println(ipString);
            processTorCheckFile(getTorFile(ipString), ipPredString);
        }
    }

    private static Stream<String> getTorFile(String ipString) {
        String domainName = String.format("https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=%s&port=", ipString);
        String command = "curl " + domainName;
        return executeUNIXCommand(command);

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

//    TODO: use Selenium to interact with web browser, do automatically after scanning prolog file (write report!)
//      use imperial ip as example, write result in evidence
    void processTorCheckFile(Stream<String> lines, String serverIP) {
        try {
            final int[] count = {torCount};
            final StringJoiner sj = new StringJoiner("\n");
            lines.forEach(line -> {
                if (!line.startsWith("#") && !line.startsWith("<!")) {
                    String[] ipStrings = line.split("\\.");
                    String fact = String.format("torIP([%s,%s,%s,%s], %s)",
                            ipStrings[0], ipStrings[1], ipStrings[2], ipStrings[3], serverIP);
                    sj.add(String.format("rule(case_torCheck%d(), %s, []).", count[0], fact));
                    count[0]++;
                }
            });
            torCount = count[0];
            Files.write(Paths.get(torIPFile + ".pl"), sj.toString().getBytes(), StandardOpenOption.APPEND);

        } catch (IOException e) {
            e.printStackTrace();
        }
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

    static void getVirustotalReportAndProcess(String ip) {
        GetIPAddressReport.getIPAddressReport(ip, virusTotalLogFileTemplate);
        processVirusTotalFile(virusTotalLogFileTemplate + ip, ip);
    }


    static void processVirusTotalFile(String filename, String ip) {
        try {
            String writeFile = virusTotalPrologFileTemplate + ip;
            virusTotalFiles.add(writeFile);

            BufferedReader br = new BufferedReader(new FileReader(filename));
            FileWriter w = new FileWriter(writeFile + ".pl");
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
            System.err.println(filename + " not found");
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

//    TODO: Wireshark, can it find spoofed IP? what can we use??


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

    public static void main(String[] args) {
//        ToolIntegration ti = new ToolIntegration();
//        ti.torIntegration();

//        getVirustotalReportAndProcess("173.194.36.104");
        parseSquidLogFile("squid_logs", "testagain");

    }

}
