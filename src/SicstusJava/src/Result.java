import java.util.*;

import static java.util.Collections.max;

public class Result {
    private String attack;
    private List<String> derivations;
    private Set<String> abduced;
    private Map<String, List<String>> abducedMap;
    private Map<String, Set<List<String>>> negMap;
    private final Object[] trees;

    private List<String> culprits;
    private List<Integer> maxScores;
    private List<Integer> numDs;
    private Map<String, LinkedHashSet<List<String>>> resultMap;


    public Result(String attack, Map<String, LinkedHashSet<List<String>>> resultMap,
                  Object[] trees, Set<String> abduced,
                  Map<String, List<String>> abducedMap, Map<String, Set<List<String>>> negMap) {
        this.attack = attack;
        this.resultMap = resultMap;
        this.abduced = abduced;
        this.abducedMap = abducedMap;
        this.negMap = negMap;
        this.trees = trees;

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

    public String getAbducedInfo() {
        return "Abduced predicates:\n" + abduced + "\n\nRules to prove abducibles:\n" + Utils.formatMap(abducedMap);
    }

    public String getTree(int i) {
        return trees[i].toString();
    }

    boolean hasAbduced() {
        return !abducedMap.isEmpty();
    }

    public void processCulpritInfo(Map<String, LinkedHashSet<List<String>>> resultMap, Object[] trees) {
        int acc = 0;
        for (String c : resultMap.keySet()) {
            List<Integer> scores = new ArrayList<>();
            LinkedHashSet<List<String>> ds = resultMap.get(c);
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
                                c, scores.get(i), dsArray[i], trees[acc]));
                    }
                    acc++;
                }
            }
        }
    }

    String getDerivationsForCulprit(String c, String separator) {
        StringJoiner sj = new StringJoiner(separator);
        for (List<String> d : resultMap.get(c)) {
            sj.add(d.toString());
        }
        return sj.toString();
    }

    @Override
    public String toString() {
        String s = String.format("\n%s\nCulprit(s): %s\nTree:\n%s", attack, culprits, trees);
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

    public int getNumNegDerivations() {
        int r = 0;
        for (Set<List<String>> s : negMap.values()) {
            r += s.size();
        }
        return r;
    }

//    void generateDiagram(String filename) {
//        String attack = filename.split("_")[0];
//        int count = Integer.parseInt(filename.split("_")[1].split(".")[0]);
//        int c = 0;
//        Term t = null;
//        for (Term term : allterms) {
//            if (c == count) {
//               t = term;
//                break;
//            }
//            c++;
//        }
//        DerivationNode.createDerivationAndSaveDiagram(t, attack, count);
//    }
}
