import java.io.*;
import java.util.List;
import java.util.Map;

public class Utils {
    static final String USER_EVIDENCE_FILENAME = "user_evidence.pl";
    int counter;
    Utils() {
        counter = 0;
        clearFile();
    }

    void addEvidence(String evidence) {
        counter++;
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(USER_EVIDENCE_FILENAME, true));
            bw.write(String.format("rule(case_user_f%d, %s, []).\n", counter, evidence));
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
        for (String evidence : evidences.split("\n")) {
            addEvidence(evidence);
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
}
