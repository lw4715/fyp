import com.kanishka.virustotal.dto.DomainReport;
import com.kanishka.virustotal.dto.DomainResolution;
import com.kanishka.virustotal.dto.Sample;
import com.kanishka.virustotal.dto.URL;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;

import java.io.FileWriter;

/**
 * Created by kanishka on 12/23/13.
 */
public class GetDomainReport {
    public static void main(String[] args) {
        try {
            String domain = "www.ntt62.com";
            String filename = "virustotal_domain_" + domain;
            FileWriter w = new FileWriter(filename);

            StringBuilder sb = new StringBuilder();

            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(ApiDetails.API_KEY);
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            DomainReport report = virusTotalRef.getDomainReport(domain);
            sb.append("___Domain Rport__\n");

            Sample[] communicatingSamples = report.getDetectedCommunicatingSamples();
            if (communicatingSamples != null) {
                sb.append("Communicating Samples\n");
                for (Sample sample : communicatingSamples) {
                    sb.append("SHA256 : " + sample.getSha256() + "\n");
                    sb.append("Date : " + sample.getDate() + "\n");
                    sb.append("Positives : " + sample.getPositives() + "\n");
                    sb.append("Total : " + sample.getTotal() + "\n");
                }
            }

            Sample[] detectedDownloadedSamples = report.getDetectedDownloadedSamples();
            if (detectedDownloadedSamples != null) {
                sb.append("Detected Downloaded Samples\n");
                for (Sample sample : detectedDownloadedSamples) {
                    sb.append("SHA256 : " + sample.getSha256() + "\n");
                    sb.append("Date : " + sample.getDate() + "\n");
                    sb.append("Positives : " + sample.getPositives() + "\n");
                    sb.append("Total : " + sample.getTotal() + "\n");
                }
            }

            URL[] urls = report.getDetectedUrls();
            if (urls != null) {
                sb.append("Detected URLs\n");
                for (URL url : urls) {
                    sb.append("URL : " + url.getUrl() + "\n");
                    sb.append("Positives : " + url.getPositives() + "\n");
                    sb.append("Total : " + url.getTotal() + "\n");
                    sb.append("Scan Date" + url.getScanDate() + "\n");
                }
            }

            DomainResolution[] resolutions = report.getResolutions();
            if (resolutions != null) {
                sb.append("Resolutions\n");
                for (DomainResolution resolution : resolutions) {
                    sb.append("IP Address : " + resolution.getIpAddress() + "\n");
                    sb.append("Last Resolved : " + resolution.getLastResolved() + "\n");
                }
            }

            Sample[] unDetectedDownloadedSamples = report.getUndetectedDownloadedSamples();
            if (unDetectedDownloadedSamples != null) {
                sb.append("Undetected Downloaded Samples\n");
                for (Sample sample : unDetectedDownloadedSamples) {
                    sb.append("SHA256 : " + sample.getSha256() + "\n");
                    sb.append("Date : " + sample.getDate() + "\n");
                    sb.append("Positives : " + sample.getPositives() + "\n");
                    sb.append("Total : " + sample.getTotal() + "\n");
                }
            }

            Sample[] unDetectedCommunicatingSamples = report.getUndetectedCommunicatingSamples();
            if (unDetectedCommunicatingSamples != null) {
                sb.append("Undetected Communicating Samples\n");
                for (Sample sample : unDetectedCommunicatingSamples) {
                    sb.append("SHA256 : " + sample.getSha256() + "\n");
                    sb.append("Date : " + sample.getDate() + "\n");
                    sb.append("Positives : " + sample.getPositives() + "\n");
                    sb.append("Total : " + sample.getTotal() + "\n");
                }
            }

            sb.append("Response Code : " + report.getResponseCode() + "\n");
            sb.append("Verbose Message : " + report.getVerboseMessage() + "\n");


        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
}
