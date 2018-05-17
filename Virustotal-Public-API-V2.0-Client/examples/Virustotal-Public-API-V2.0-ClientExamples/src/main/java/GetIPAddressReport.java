import com.kanishka.virustotal.dto.IPAddressReport;
import com.kanishka.virustotal.dto.IPAddressResolution;
import com.kanishka.virustotal.dto.Sample;
import com.kanishka.virustotal.dto.URL;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;
import javafx.util.Pair;
import systemtests.config.ApiDetails;

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by kanishka on 12/23/13.
 */
public class GetIPAddressReport {

    // return <<year, month>, hostname>
    public static List<Pair<Pair<Integer, Integer>, String>> getIPResolution(String ip) {
        VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(ApiDetails.API_KEY());
//        List rs = new ArrayList<>();
        try {
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();
            System.out.println(ip);
            IPAddressReport report = virusTotalRef.getIPAddresReport(ip);
            IPAddressResolution[] resolutions = report.getResolutions();

            List<Pair<Pair<Integer, Integer>, String>> ret = new ArrayList<>();
            if (resolutions != null) {
                for (IPAddressResolution resolution : resolutions) {
                    String[] d = resolution.getLastResolved().split(" ")[0].split("-");
//                    String date = String.format("[%d,%d]", Integer.parseInt(d[0]), Integer.parseInt(d[1]));
                    int year = Integer.parseInt(d[0]);
                    int month = Integer.parseInt(d[1]);
                    Pair<Integer, Integer> date = new Pair<>(year, month);
                    ret.add(new Pair<>(date, resolution.getHostName()));
//                    rs.add(new String[]{resolution.getHostName(), resolution.getLastResolved()});
                }
            }
            return ret;
        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
        return null;
    }

    public static void getIPAddressReport(String ip, String basefilename) {
        try {
//            String ip = "69.195.124.58";
            String filename = basefilename + ip;
            FileWriter w = new FileWriter(filename);

            StringBuilder sb = new StringBuilder();
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(ApiDetails.API_KEY());
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            IPAddressReport report = virusTotalRef.getIPAddresReport(ip);

            sb.append("___IP Report__\n");

            Sample[] communicatingSamples = report.getDetectedCommunicatingSamples();
            if (communicatingSamples != null) {
                sb.append("\nCommunicating Samples\n");
                for (Sample sample : communicatingSamples) {
                    sb.append("SHA256 : " + sample.getSha256() + "\n");
                    sb.append("Date : " + sample.getDate() + "\n");
                    sb.append("Positives : " + sample.getPositives() + "\n");
                    sb.append("Total : " + sample.getTotal() + "\n");
                }
            }

            Sample[] detectedDownloadedSamples = report.getDetectedDownloadedSamples();
            if (detectedDownloadedSamples != null) {
                sb.append("\nDetected Downloaded Samples" + "\n");
                for (Sample sample : detectedDownloadedSamples) {
                    sb.append("SHA256 : " + sample.getSha256() + "\n");
                    sb.append("Date : " + sample.getDate() + "\n");
                    sb.append("Positives : " + sample.getPositives() + "\n");
                    sb.append("Total : " + sample.getTotal() + "\n");
                }
            }

            URL[] urls = report.getDetectedUrls();
            if (urls != null) {
                sb.append("\nDetected URLs" + "\n");
                for (URL url : urls) {
                    sb.append("URL : " + url.getUrl() + "\n");
                    sb.append("Positives : " + url.getPositives() + "\n");
                    sb.append("Total : " + url.getTotal() + "\n");
                    sb.append("Scan Date" + url.getScanDate() + "\n");
                }
            }

            IPAddressResolution[] resolutions = report.getResolutions();
            if (resolutions != null) {
                sb.append("\nResolutions\n");
                for (IPAddressResolution resolution : resolutions) {
                    sb.append("Host Name : " + resolution.getHostName() + "\n");
                    sb.append("Last Resolved : " + resolution.getLastResolved() + "\n");
                }
            }

            Sample[] unDetectedDownloadedSamples = report.getUndetectedDownloadedSamples();
            if (unDetectedDownloadedSamples != null) {
                sb.append("\nUndetected Downloaded Samples\n");
                for (Sample sample : unDetectedDownloadedSamples) {
                    sb.append("SHA256 : " + sample.getSha256() + "\n");
                    sb.append("Date : " + sample.getDate() + "\n");
                    sb.append("Positives : " + sample.getPositives() + "\n");
                    sb.append("Total : " + sample.getTotal() + "\n");
                }
            }

            Sample[] unDetectedCommunicatingSamples = report.getUndetectedCommunicatingSamples();
            if (unDetectedCommunicatingSamples != null) {
                sb.append("\nUndetected Communicating Samples\n");
                for (Sample sample : unDetectedCommunicatingSamples) {
                    sb.append("SHA256 : " + sample.getSha256() + "\n");
                    sb.append("Date : " + sample.getDate() + "\n");
                    sb.append("Positives : " + sample.getPositives() + "\n");
                    sb.append("Total : " + sample.getTotal() + "\n");
                }
            }

            sb.append("Response Code : " + report.getResponseCode() + "\n");
            sb.append("Verbose Message : " + report.getVerboseMessage() + "\n");

            w.write(sb.toString());
            w.close();

        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }

    public static void main(String[] args) {
        getIPAddressReport("173.194.36.104", "testingname");
    }

}
