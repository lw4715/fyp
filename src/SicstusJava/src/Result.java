import java.util.List;
import java.util.Map;
import java.util.Set;

public class Result {
    private String attack;
    private List<String> culpritString;
    private Set<String> abduced;
    private Map<String, List<String>> abducedMap;
//    private Map<String, Term>[] derivations;

    Result(String attack, List<String> culpritString,
           Set<String> abduced, Map<String,
            List<String>> abducedMap) {
        this.attack = attack;
        this.culpritString = culpritString;
        this.abduced = abduced;
        this.abducedMap = abducedMap;
//        this.derivations = derivations;
    }

    public String getAttack() {
        return this.attack;
    }

    boolean hasAbduced() {
        return !abducedMap.isEmpty();
    }


    @Override
    public String toString() {
        String s = String.format("\n%s\nCulprit(s): %s\n", attack, this.culpritString);
        if (abducedMap.isEmpty()) {
            return s;
        } else {
            return String.format("%s\nAbduced: %s\n\nPossible additional evidences needed:\n%s",
                    s, abduced, Utils.formatMap(abducedMap));
        }

    }

    public String getHeader() {
        return this.culpritString.get(0);
    }

    public List<String> resultStrings() {
        return this.culpritString.subList(1, culpritString.size() - 1);
    }
}
