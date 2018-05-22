import javafx.util.Pair;

import java.util.*;

import static java.util.Collections.max;

public class Result {
    private String attack;
    private List<Pair<String, Pair<List<String>, String>>> derivations;
    private Set<String> abduced;
    private Map<String, List<String>> abducedMap;
    private Map<String, Set<List<String>>> negMap;
    private final Object[] trees;
    private List<Object> filteredTrees;

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
        filteredTrees = new ArrayList<>();
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

    // int i iterates over *all* culprits
    public String getTree(int i) {
        return filteredTrees.get(i).toString();
    }

    boolean hasAbduced() {
        return !abducedMap.isEmpty();
    }

    public void filterByStrRulePrefs(List<Pair<String, String>> strRulePrefs) {
        maxScores.clear();
        culprits.clear();
        numDs.clear();
        filteredTrees.clear();
        if (strRulePrefs.isEmpty()) {
            processCulpritInfo();
        } else {
            Collections.addAll(filteredTrees, trees);
            for (String c : resultMap.keySet()) {
                LinkedHashSet<List<String>> ds = resultMap.get(c);
            }


            Set<String> nonpreferredStrRules = new HashSet<>();

            // find all preferred rules (to override nonpreferred rules)
            for (Pair<String, Pair<List<String>, String>> derivation : derivations) {
                for (Pair<String, String> strRulePref : strRulePrefs) {
                    String preferredStrRule = strRulePref.getKey();
                    String nonpreferredStrRule = strRulePref.getValue();

                    if (derivation.getValue().toString().contains(preferredStrRule)) {
                        nonpreferredStrRules.add(nonpreferredStrRule);
                        break;
                    }
                }
            }

            // filter derivations
            List<Pair<String, Pair<List<String>, String>>> filteredDerivations = new ArrayList<>();

            for (int i = derivations.size() - 1; i >=0 ; i--) {
                List<String> d = derivations.get(i).getValue().getKey();
                boolean found = false;
                for (String nonpreferredStrRule : nonpreferredStrRules) {
                    if (d.toString().contains(nonpreferredStrRule)) {
                        found = true;
                        filteredTrees.remove(i);
                        break;
                    }
                }
                if (!found) {
                    filteredDerivations.add(derivations.get(i));
                }
            }

            derivations = filteredDerivations;

            // re-process for summary
            String currCulprit = null;
            int numDsAcc = 0;
            List<Integer> scores = new ArrayList<>();
            scores.add(0);
            for (Pair<String, Pair<List<String>, String>> derivation : derivations) {
                String c = derivation.getValue().getValue();
                List<String> d = derivation.getValue().getKey();
                if (currCulprit == null) {
                    currCulprit = c;
                    culprits.add(c);
                } else if (!currCulprit.equals(c)) {
                    maxScores.add(max(scores));
                    culprits.add(c);
                    numDs.add(numDsAcc);
                    currCulprit = c;
                    scores.clear();
                    scores.add(0);
                    numDsAcc = 0;
                }
                scores.add(QueryExecutor.getScore(d));
                numDsAcc++;
            }
            // last derivation is missed out
            maxScores.add(max(scores));
            numDs.add(numDsAcc);
        }
    }


    //derivations contain: <Formatted String, <Derivation (List), Culprit (String)>>
    public void processCulpritInfo() {
        Collections.addAll(filteredTrees, trees);

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

                int i = 0;
                for (List<String> d : ds) {
                    if (scores.get(i) > 0) {
                        String strFinalRule = getFinalRule((List<String>) dsArray[i]);
                        String fullString = String.format(
                                "X = %s, Score:%d\nFinal strategic rule used: %s\n\n" +
                                        "Derivation:\n%s\n\nArgumentation Tree:\n %s",
                                c, scores.get(i), strFinalRule, d, trees[acc]);
                        derivations.add(new Pair<>(fullString, new Pair<>(d, c)));
                    }
                    acc++;
                    i++;
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
        maxScores.clear();
        culprits.clear();
        numDs.clear();
        filteredTrees.clear();
        processCulpritInfo();
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
//            System.out.println("C:" + culprits + " S:" + maxScores + " Ds:" + numDs);
            sb.append(String.format("X = %s [Highest score: %d, Num of derivations: %d]\n",
                    culprits.get(i), maxScores.get(i), numDs.get(i)));
        }
        return sb.toString();
    }

    static String getFinalRule(List<String> ds) {
        for (int i = ds.size() - 1; i >= 0 ; i--) {
            String d1 = ds.get(i);
            if (Utils.isFinalStrRule(d1)) {
                return d1;
            }
        }

        // if doesn't follow pattern, maybe its just the last one
        return ds.get(ds.size() - 1);
    }


    public List<Pair<String, Pair<List<String>, String>>> resultStrings() {
        return derivations;
    }

    // Return all derivation (first in pair), joined by separator, excluding the ones with same strRule
    public String getDerivationsWithDiffStrRule(String separator, int excludeIndex) {
        String strRule = getFinalRule(derivations.get(excludeIndex).getValue().getKey());
        StringJoiner sj = new StringJoiner(separator);
        for (int i = 0; i < derivations.size(); i++) {
            if (i != excludeIndex && !getFinalRule(derivations.get(i).getValue().getKey()).equals(strRule)) {
                Pair<String, Pair<List<String>, String>> derivation = derivations.get(i);
                sj.add(derivation.getValue().getKey().toString());
            }
        }
        return sj.toString();
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
        Set<String> culprits = new HashSet<>();
        for (Pair<String, Pair<List<String>, String>> derivation : derivations) {
            String culprit = derivation.getValue().getValue();
            culprits.add(culprit);
        }

        for (String culprit : culprits) {
            if (negMap.get(culprit) != null) {
                r += negMap.get(culprit).size();
            }
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
