import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;
import java.util.stream.Stream;
//import

public class ToolIntegration {
    static final String targetServerIPPredicate = "targetServerIP";
    static final String torIPFile = "torCheckIPList";
    static final String virusTotalPrologFileTemplate = "virustotal_";
    static final String virusTotalLogFileTemplate = "virustotal_res_";
    static final List<String> virusTotalFiles = new ArrayList<>();

    static void torIntegration() {
        List<String[]> ips = getTargetServerIP(Utils.EVIDENCE_FILENAME);
        System.out.println(ips.size() + " server IPs found!");
        for (String[] ip : ips) {
            String ipPredString = String.format("[%s,%s,%s,%s]", ip[0], ip[1], ip[2], ip[3]);
            String ipString = String.format("%s.%s.%s.%s", ip[0], ip[1], ip[2], ip[3]);
            System.out.println(ipString);
            processTorCheckFile(getTorFile(ipString), ipPredString);
        }
    }

    private static Stream<String> getTorFile(String ipString) {
        URL torURL = null;
        try {
            String url = String.format("https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=%s&port=", ipString);
            torURL = new URL(url);
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(torURL.openStream()));
            in.lines().forEach(x -> System.out.println(x));
            return in.lines();
        } catch (MalformedURLException e) {
            System.err.println("Malformed");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("IO exception!");
            e.printStackTrace();
        }

        return null;
    }

    static List<String[]> getTargetServerIP(String filename) {
        List<String[]> ips = new ArrayList<>();
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
    static void processTorCheckFile(Stream<String> lines, String serverIP) {
        try {
            final int[] count = {0};
            final StringJoiner sj = new StringJoiner("\n");
            lines.forEach(line -> {
                if (!line.startsWith("#") && !line.startsWith("<!")) {
                    System.out.println(line);
                    String[] ipStrings = line.split("\\.");
                    String fact = String.format("torIP([%s,%s,%s,%s], %s)",
                            ipStrings[0], ipStrings[1], ipStrings[2], ipStrings[3], serverIP);
                    sj.add(String.format("rule(case_torCheck%d(), %s, []).", count[0], fact));
                    count[0]++;
                }
            });

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
            int c = 0;
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

//    static void getVirustotalReportAndProcess(String ip) {
//        getIPAddressReport(ip);
//        processVirusTotalFile(virusTotalLogFileTemplate + ip, ip);
//    }


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
//

//    public static void main(String[] args) {
////        processTorCheckFile("check_tor.txt", "72.111.1.30");
////        System.out.println(ipGeolocation("82.8.188.204"));
//        processVirusTotalFile("/Users/linna/FYP/fyp/Virustotal-Public-API-V2.0-Client/virustotal_res_69.195.124.58", "69.195.124.58");
//    }


    public static void main(String[] args) {
        torIntegration();
    }
}
