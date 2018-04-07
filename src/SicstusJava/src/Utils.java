import java.io.*;

public class Utils {
    static final String USER_EVIDENCE_FILENAME = "../Prolog_files/user_evidence.pl";
    int counter;
    Utils() {
        counter = 0;
        clearFile();
    }

    void addEvidence(String evidence) {
        counter++;
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(USER_EVIDENCE_FILENAME, true));
            bw.write(String.format("rule(usercase_f%d, %s, []).\n", counter, evidence));
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
        writer.print("");
        writer.close();
    }

    public void updateEvidence(String evidences) {
        clearFile();
        for (String evidence : evidences.split("\n")) {
            addEvidence(evidence);
        }
    }
}
