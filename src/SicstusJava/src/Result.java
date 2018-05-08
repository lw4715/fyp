import java.util.*;

import static java.util.Collections.max;

public class Result {
    private String attack;
    private List<String> derivations;
    private Set<String> abduced;
    private Map<String, List<String>> abducedMap;
    private Map<String, Set<List<String>>> negMap;

    private List<String> culprits;
    private List<Integer> maxScores;
    private List<Integer> numDs;
    private LinkedHashSet<List<String>> ds;

    public Result(String attack, Map<String, LinkedHashSet<List<String>>> resultMap,
                  Object[] trees, Set<String> abduced, Map<String,
            List<String>> abducedMap, Map<String, Set<List<String>>> negMap) {
        this.attack = attack;
        this.abduced = abduced;
        this.abducedMap = abducedMap;
        this.negMap = negMap;
        culprits = new ArrayList<>();
        maxScores = new ArrayList<>();
        numDs = new ArrayList<>();
        derivations = new ArrayList<>();
        processCulpritInfo(resultMap, trees);
    }

    public String getAttack() {
        return this.attack;
    }

    public List<String> getCulprits() {
        return this.culprits;
    }

    boolean hasAbduced() {
        return !abducedMap.isEmpty();
    }

    public void processCulpritInfo(Map<String, LinkedHashSet<List<String>>> resultMap, Object[] trees) {
        for (String c : resultMap.keySet()) {
            List<Integer> scores = new ArrayList<>();
            ds = resultMap.get(c);
            if (!ds.isEmpty()) {
                for (List<String> d : ds) {
                    scores.add(QueryExecutor.getScore(d));
                }

                if (max(scores) > 0) {

                    culprits.add(c);
                    maxScores.add(max(scores));
                    numDs.add(ds.size());
                }

                Object[] dsArray = ds.toArray();

                for (int i = 0; i < ds.size(); i++) {
                    if (scores.get(i) > 0) {
                        derivations.add(String.format("X = %s, Score:%d\n\nDerivation:\n%s\n\nArgumentation Tree:\n %s",
                                c, scores.get(i), dsArray[i], trees[i]));
                    }
                }
            }
        }
    }

//    String getDerivation(int i) {
//        return ds.toArray()[i].toString();
//    }

    String getAllDerivations() {
        StringJoiner sj = new StringJoiner("#");
        for (List<String> d : ds) {
            sj.add(d.toString());
        }
        return sj.toString();
    }

    @Override
    public String toString() {
        String s = String.format("\n%s\nCulprit(s): %s\n", attack, culprits);
        if (abducedMap.isEmpty()) {
            return s;
        } else {
            return String.format("%s\nAbduced: %s\n\nPossible additional evidences needed:\n%s",
                    s, abduced, Utils.formatMap(abducedMap));
        }

    }

    public String getCulpritsSummary() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < culprits.size(); i++) {
            sb.append(String.format("X = %s [Highest score: %d, Num of derivations: %d]\n",
                    culprits.get(i), maxScores.get(i), numDs.get(i)));
        }
        return sb.toString();
    }

    public List<String> resultStrings() {
        return derivations;
    }

    public List<String> negDerivationFor(String culprit) {
        List<String> ret = new ArrayList<>();
        Set<List<String>> dss = negMap.get(culprit);
        if (dss == null) {
            return ret;
        }
        for (List<String> ds : dss) {
            StringJoiner sj = new StringJoiner(", ");
            for (String d : ds) {
                sj.add(d);
            }
            ret.add("[" + sj.toString() + "]");
        }
        return ret;
    }

    public boolean hasNegDerivations() {
        return !negMap.isEmpty();
    }

    public Map<String, Set<List<String>>> getNegMap() {
        return negMap;
    }
}
