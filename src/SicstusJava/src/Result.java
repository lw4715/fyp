import java.util.List;
import java.util.Map;
import java.util.Set;

public class Result {

    private String culpritString;
    private Map<String, Integer> techMap;
    private Map<String, Integer> opMap;
    private Map<String, Integer> strMap;
    private Set<String> abduced;
    private Map<String, List<String>> abducedMap;

    Result(String culpritString, Map<String, Integer> techMap, Map<String, Integer> opMap,
           Map<String, Integer> strMap, Set<String> abduced, Map<String,
            List<String>> abducedMap) {
        this.culpritString = culpritString;
        this.techMap = techMap;
        this.opMap = opMap;
        this.strMap = strMap;
        this.abduced = abduced;
        this.abducedMap = abducedMap;
    }

    boolean hasAbduced() {
        return !abducedMap.isEmpty();
    }



    @Override
    public String toString() {
        String s = String.format("Culprit(s): %s\nTech: %s\nOp: %s\nStr: %s\n",
                this.culpritString, this.techMap, this.opMap, this.strMap);
        if (abducedMap.isEmpty()) {
            return s;
        } else {
            return String.format("%s\nAbduced: %s\n\nPossible additional evidences needed:\n%s", s, abduced, format(abducedMap));
        }

    }

    private String format(Map<String, List<String>> abducedMap) {
        StringBuilder sb = new StringBuilder();
        for (String k : abducedMap.keySet()) {
            sb.append(k);
            sb.append(": {");
            for (String v : abducedMap.get(k)) {
                sb.append("\n\t\t");
                sb.append(v);
            }
            sb.append("}\n");
        }
        return sb.toString();
    }
}
