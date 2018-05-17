import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;
import systemtests.config.ApiDetails;

import java.io.File;
import java.io.UnsupportedEncodingException;

/**
 * Created by kanishka on 12/23/13.
 */
public class ScanFile {
    public static String getFileResource(File f) {
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(ApiDetails.API_KEY());
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();
            return virusTotalRef.scanFile(f).getResource();
        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
        return null;
    }
    public static void main(String[] args) {

        System.out.println(getFileResource(new File("/Users/linna/Downloads/2015-08-31-traffic-analysis-exercise.pcap")));
//
//        try {
//            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(ApiDetails.API_KEY());
//            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();
//
//            ScanInfo scanInformation = virusTotalRef.scanFile(new File("/Users/linna/Downloads/2015-08-31-traffic-analysis-exercise.pcap"));
//
//            System.out.println("___SCAN INFORMATION___");
//            System.out.println("MD5 :\t" + scanInformation.getMd5());
//            System.out.println("Perma Link :\t" + scanInformation.getPermalink());
//            System.out.println("Resource :\t" + scanInformation.getResource());
//            System.out.println("Scan Date :\t" + scanInformation.getScanDate());
//            System.out.println("Scan Id :\t" + scanInformation.getScanId());
//            System.out.println("SHA1 :\t" + scanInformation.getSha1());
//            System.out.println("SHA256 :\t" + scanInformation.getSha256());
//            System.out.println("Verbose Msg :\t" + scanInformation.getVerboseMessage());
//            System.out.println("Response Code :\t" + scanInformation.getResponseCode());
//            System.out.println("done.");
//        } catch (APIKeyNotFoundException ex) {
//            System.err.println("API Key not found! " + ex.getMessage());
//        } catch (UnsupportedEncodingException ex) {
//            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
//        } catch (UnauthorizedAccessException ex) {
//            System.err.println("Invalid API Key " + ex.getMessage());
//        } catch (Exception ex) {
//            System.err.println("Something Bad Happened! " + ex.getMessage());
//        }
    }
}
