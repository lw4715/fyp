import se.sics.jasper.SPTerm;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;

public class Result {

    private String culpritString;
    private Map<String, Integer> techMap;
    private Map<String, Integer> opMap;
    private Map<String, Integer> strMap;
    private Set<String> abduced;
    private Map<String, List<String>> abducedMap;
    private SPTerm[] derivations;

    Result(String culpritString, Map<String, Integer> techMap, Map<String, Integer> opMap,
           Map<String, Integer> strMap, Set<String> abduced, Map<String,
            List<String>> abducedMap, SPTerm[] derivations) {
        this.culpritString = culpritString;
        this.techMap = techMap;
        this.opMap = opMap;
        this.strMap = strMap;
        this.abduced = abduced;
        this.abducedMap = abducedMap;
        this.derivations = derivations;
    }

    boolean hasAbduced() {
        return !abducedMap.isEmpty();
    }

    String getDerivations() {
        StringJoiner sj = new StringJoiner(",\n");
        for (SPTerm derivation : derivations) {
            sj.add(derivation.toString());
        }
        return sj.toString();
    }



    @Override
    public String toString() {
//        String s = String.format("\nCulprit(s): %s\nTech: %s\nOp: %s\nStr: %s\n",
//                this.culpritString, this.techMap, this.opMap, this.strMap);

        String s = String.format("\nCulprit(s): %s\n", this.culpritString);
        if (abducedMap.isEmpty()) {
            return s;
        } else {
            return String.format("%s\nAbduced: %s\n\nPossible additional evidences needed:" +
                    "\n%s", s, abduced, Utils.formatMap(abducedMap));
        }

    }
}
