import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;
//import

public class ToolIntegration {
    static final String torIPFile = "torCheckIPList";
    static final String virusTotalPrologFileTemplate = "virustotal_";
    static final String virusTotalLogFileTemplate = "virustotal_res_";
    static final List<String> virusTotalFiles = new ArrayList<>();

    static void processTorCheckFile(String filename, String serverIP) {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
//            String[] s = serverIP.split("\\.");
//            String serverIPString = String.format("%s_%s_%s_%s", s[0], s[1], s[2], s[3]);
            FileWriter w = new FileWriter(torIPFile + ".pl");
            String line = br.readLine();
            int count = 0;
            while (line != null) {
                if (!line.startsWith("#")) {
                    String[] ipStrings = line.split("\\.");
                    String fact = String.format("torIP([%s,%s,%s,%s])",
                            ipStrings[0], ipStrings[1], ipStrings[2], ipStrings[3]);
                    w.write(String.format("rule(case_torCheck%d(), %s, []).\n", count, fact));
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

    public static void main(String[] args) {
//        processTorCheckFile("check_tor.txt", "72.111.1.30");
//        System.out.println(ipGeolocation("82.8.188.204"));
        processVirusTotalFile("/Users/linna/FYP/fyp/Virustotal-Public-API-V2.0-Client/virustotal_res_69.195.124.58", "69.195.124.58");
    }
}
