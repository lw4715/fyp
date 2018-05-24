//import javafx.util.Pair;
import com.sun.tools.javac.util.Pair;

import java.util.*;

import static java.util.Collections.max;

public class Result {
    private final String attack;
    private final Set<String> abduced;
    private final Map<String, List<String>> abducedMap;
    private final Map<String, Set<List<String>>> negMap;
    private final Object[] trees;
    //derivations = fst: fullString snd: {fst1: derivation, snd1: culprit}
    private List<Pair<String, Pair<List<String>, String>>> derivations;
    private final Map<String, LinkedHashSet<List<String>>> resultMap;

    // NOTE: to clear each round
    private final List<String> culprits;
    private final List<Integer> maxScores;
    private final List<Integer> numDs;
    private final List<Object> filteredTrees;
    private HashSet<String> nonpreferredStrRules;


    public Result(String attack, Map<String, LinkedHashSet<List<String>>> resultMap,
                  Object[] trees, Set<String> abduced,
                  Map<String, List<String>> abducedMap, Map<String, Set<List<String>>> negMap) {
        this.attack = attack;
        this.resultMap = resultMap;
        this.abduced = abduced;
        this.abducedMap = abducedMap;
        this.negMap = negMap;
        this.trees = trees;

        this.culprits = new ArrayList<>();
        this.maxScores = new ArrayList<>();
        this.numDs = new ArrayList<>();
        this.derivations = new ArrayList<>();
        this.filteredTrees = new ArrayList<>();
    }

//    public String getAttack() {
//        return this.attack;
//    }

    public List<String> getCulprits() {
        return culprits;
    }

    public String getAbducedInfo() {
        return "Abduced predicates:\n" + this.abduced + "\n\nRules to prove abducibles:\n" + Utils.formatMap(this.abducedMap);
    }

    // int i iterates over *all* culprits
    public String getTree(int i) {
        return this.filteredTrees.get(i).toString();
    }

    boolean hasAbduced() {
        return !this.abducedMap.isEmpty();
    }

    public void filterByStrRulePrefs(List<Pair<String, String>> strRulePrefs) {
        System.out.println("filterByStrRulePrefs? " + strRulePrefs.size() );
        if (strRulePrefs.isEmpty()) {
            // no custom prefs, proceed as normal
            this.maxScores.clear();
            this.culprits.clear();
            this.numDs.clear();
            this.filteredTrees.clear();
            this.derivations.clear();
            this.processCulpritInfo();

        } else {
            if (this.derivations.isEmpty()) {
                this.processCulpritInfo(); // populate derivations for the first time
            }
            this.maxScores.clear();
            this.culprits.clear();
            this.numDs.clear();
            this.filteredTrees.clear();

            System.out.println("Filtering...");
            this.nonpreferredStrRules = new HashSet<>();
            // find all preferred rules (to override nonpreferred rules)
            for (Pair<String, Pair<List<String>, String>> derivation : this.derivations) {
                for (Pair<String, String> strRulePref : strRulePrefs) {
                    String preferredStrRule = strRulePref.fst;
                    String nonpreferredStrRule = strRulePref.snd;

                    if (derivation.snd.fst.toString().contains(preferredStrRule)) {
                        this.nonpreferredStrRules.add(nonpreferredStrRule);
                        break;
                    }
                }
            }

            // filter derivations
            List<Pair<String, Pair<List<String>, String>>> filteredDerivations = new ArrayList<>();

            for (int i = this.derivations.size() - 1; i >=0 ; i--) {
                List<String> d = this.derivations.get(i).snd.fst;
                boolean found = false;
                for (String nonpreferredStrRule : this.nonpreferredStrRules) {
                    if (d.toString().contains(nonpreferredStrRule)) {
                        System.out.println(d + " contains " + nonpreferredStrRule);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    this.filteredTrees.add(this.trees[i]);
                    filteredDerivations.add(this.derivations.get(i));
                    System.out.println("filtered Derivations: " + filteredDerivations);
                }
            }

            this.derivations = filteredDerivations;

            // re-process for summary
            String currCulprit = null;
            int numDsAcc = 0;
            List<Integer> scores = new ArrayList<>();
            scores.add(0);
            for (Pair<String, Pair<List<String>, String>> derivation : this.derivations) {
                String c = derivation.snd.snd;
                List<String> d = derivation.snd.fst;
                if (currCulprit == null) {
                    currCulprit = c;
                    this.culprits.add(c);
                } else if (!currCulprit.equals(c)) {
                    this.maxScores.add(max(scores));
                    this.culprits.add(c);
                    this.numDs.add(numDsAcc);
                    currCulprit = c;
                    scores.clear();
                    scores.add(0);
                    numDsAcc = 0;
                }
                scores.add(Utils.getScore(d));
                numDsAcc++;
            }
            // last derivation is missed out
            this.maxScores.add(max(scores));
            this.numDs.add(numDsAcc);
        }
    }


    //derivations contain: <Formatted String, <Derivation (List), Culprit (String)>>
    public void processCulpritInfo() {
        Collections.addAll(this.filteredTrees, this.trees);

        int acc = 0;
        for (String c : this.resultMap.keySet()) {
            List<Integer> scores = new ArrayList<>();
            LinkedHashSet<List<String>> ds = this.resultMap.get(c);
            if (!ds.isEmpty()) {
                for (List<String> d : ds) {
                    scores.add(Utils.getScore(d));
                }

                if (max(scores) > 0) {
                    this.culprits.add(c);
                    this.maxScores.add(max(scores));
                    this.numDs.add(ds.size());
                }

                Object[] dsArray = ds.toArray();

                int i = 0;
                for (List<String> d : ds) {
                    if (scores.get(i) > 0) {
                        String strFinalRule = Result.getFinalRule((List<String>) dsArray[i]);
                        String fullString = String.format(
                                "X = %s, Score:%d\nFinal strategic rule used: %s\n\n" +
                                        "Derivation:\n%s\n\nArgumentation Tree:\n %s",
                                c, scores.get(i), strFinalRule, d, this.trees[acc]);
                        this.derivations.add(new Pair<>(fullString, new Pair<>(d, c)));
                    }
                    acc++;
                    i++;
                }
            }
        }
    }

    String getDerivationsForCulprit(String c, String separator) {
        StringJoiner sj = new StringJoiner(separator);
        for (List<String> d : this.resultMap.get(c)) {
            boolean include = true;
            if (this.nonpreferredStrRules != null) {
                for (String nonpreferredStrRule : this.nonpreferredStrRules) {
                    if (d.toString().contains(nonpreferredStrRule)) {
                        include = false;
                        break;
                    }
                }
            }
            if (include) {
                sj.add(d.toString());
            }
        }
        return sj.toString();
    }


    @Override
    public String toString() {
        this.maxScores.clear();
        this.culprits.clear();
        this.numDs.clear();
        this.filteredTrees.clear();
        this.processCulpritInfo();
        String s = String.format("\n%s\nCulprit(s): %s\nTree:\n%s", this.attack, this.culprits, this.trees);
        if (this.abducedMap.isEmpty()) {
            return s;
        } else {
            return String.format("%s\nAbduced: %s\n\nPossible additional evidences needed:\n%s",
                    s, this.abduced, Utils.formatMap(this.abducedMap));
        }

    }

    public String getCulpritsSummary() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < this.culprits.size(); i++) {
//            System.out.println("C:" + culprits + " S:" + maxScores + " Ds:" + numDs);
            sb.append(String.format("X = %s [Highest score: %d, Num of derivations: %d]\n",
                    this.culprits.get(i), this.maxScores.get(i), this.numDs.get(i)));
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

    // format of d:
    // [p4a_t(), case_autogen_geolocation_0(), case_example2b_f9(), r_t_srcIP1(china, example2b),
    // r_t_attackOrigin(china, example2b), bg67(), r_str__loc(china, example2b)]
    public static String getFinalRule(String d) {
        d = d.substring(1, d.length() - 1);
        String ruleRegex = "\\b[(a-z)|(A-Z)|(0-9)|_]*\\([^\\)]*\\)";
        return Result.getFinalRule(Utils.regexMatch(ruleRegex, d));
    }


    public List<Pair<String, Pair<List<String>, String>>> resultStrings() {
        return this.derivations;
    }

    // Return all derivation (first in pair), joined by separator, excluding the ones with same strRule
    public String getDerivationsWithDiffStrRule(String separator, int excludeIndex) {
        String strRule = Result.getFinalRule(this.derivations.get(excludeIndex).snd.fst);
        StringJoiner sj = new StringJoiner(separator);
        for (int i = 0; i < this.derivations.size(); i++) {
            if (i != excludeIndex && !Result.getFinalRule(this.derivations.get(i).snd.fst).equals(strRule)) {
                Pair<String, Pair<List<String>, String>> derivation = this.derivations.get(i);
                sj.add(derivation.snd.fst.toString());
            }
        }
        return sj.toString();
    }

    public List<String> negDerivationFor(String culprit) {
        List<String> ret = new ArrayList<>();
        Set<List<String>> dss = this.negMap.get(culprit);
        if (dss == null) {
            return ret;
        }
        for (List<String> ds : dss) {
            StringJoiner sj = new StringJoiner(", ");
            for (String d : ds) {
                sj.add(d);
            }
            ret.add("[" + sj + "]");
        }
        return ret;
    }

    public boolean hasNegDerivations() {
        return !this.negMap.isEmpty();
    }

    public int getNumNegDerivations() {
        int r = 0;
        Set<String> culprits = new HashSet<>();
        for (Pair<String, Pair<List<String>, String>> derivation : this.derivations) {
            String culprit = derivation.snd.snd;
            culprits.add(culprit);
        }

        for (String culprit : culprits) {
            if (this.negMap.get(culprit) != null) {
                r += this.negMap.get(culprit).size();
            }
        }
        return r;
    }

    public static void main(String[] args) {
        System.out.println(Result.getFinalRule("[p4a_t(), case_autogen_geolocation_0(), case_example2b_f9(), r_t_srcIP1(china, example2b), r_t_attackOrigin(china, example2b), bg67(), r_str__loc(china, example2b)]"));
    }

}
