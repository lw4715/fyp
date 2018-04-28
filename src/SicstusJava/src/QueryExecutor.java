import org.jpl7.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.lang.Integer;
import java.util.*;

import static java.lang.Math.pow;
import static java.util.Collections.max;

@SuppressWarnings("ALL")
public class QueryExecutor {
    private static final String VISUALLOG = "visual.log";
    private final boolean VERBOSE = false;

    private static final QueryExecutor instance = new QueryExecutor();
    private static String FILEPATH = "";
    private static final String CONSULT_STRING = "consult(%s)";
    private static final String TECH = FILEPATH + "tech_rules";
    private static final String OP = FILEPATH + "op_rules";
    private static final String STR = FILEPATH + "str_rules";
//    private static final String TECHSAV = "tech.sav";
//    private static final String OPSAV = "op.sav";
//    private static final String STRSAV = "str.sav";

    private Set<String> abduced;

    public static QueryExecutor getInstance() {
        return instance;
    }

    private QueryExecutor() {
        JPL.init();
        abduced = new HashSet<>();
    }

    private LinkedHashSet<String> getVisualTree() {
        try {
            File f = new File(VISUALLOG);
            BufferedReader br = new BufferedReader(new FileReader(VISUALLOG));
            StringBuilder sb = new StringBuilder();
            br.lines().forEach(line -> {
                sb.append(line + "\n");
            });
            LinkedHashSet<String> set = new LinkedHashSet<>();
            String[] split = sb.toString().split("\n\n\n");
            for (int i = 0; i < split.length; i++) {
                String s = split[i];
                set.add(s);
            }
            return set;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    public String culpritString(String attack, Map<String, LinkedHashSet<List<String>>> resultMap, Map<String, Set<List<String>>> negMap, Object[] visualTree) {
        StringJoiner sj = new StringJoiner(",");
        for (String c : resultMap.keySet()) {
            List<Integer> scores = new ArrayList<>();
            for (List<String> d : resultMap.get(c)) {
                scores.add(getScore(d));
            }
            sj.add(String.format("%s [Highest score: %d, D: %d]\n", c,
                    max(scores),resultMap.get(c).size()));
            for (int i = 0; i < resultMap.get(c).size(); i++) {
                sj.add(String.format("X = %s [Score: %d] \nDerivation:\n %s\nNegative Derivation: %s\n", c,
                        scores.get(i), visualTree[i], negMap.get(c)));
                negMap.remove(c);
            }

        }
        return "{" + attack + "}\n" + sj;
    }

    Map<String, Term>[] executeQuery(String caseName, boolean verbose, boolean all) {
        Map<String, Integer> accMap;
        int res;
        int numDeltas;
        Map<String, Term>[] queryMap;
        String queryString;
        Set<String> queryStrings = new HashSet<>();

        try
        {
            String goal;
            if (all) {
                goal = "goal_all";
            } else {
                goal = "goal";
            }

            System.out.println("All");
            executeQueryString(String.format("tell('%s')", VISUALLOG), 1);
            queryString = String.format("%s(%s,X,D0)", goal, caseName);
            queryMap = executeQueryString(queryString, 10);
            System.out.println(queryString);
            executeQueryString("told", 1);
            return queryMap;
        } catch ( Exception e ) {
            e.printStackTrace();
            return null;
        }
    }

    private Map<String, Term>[] executeQueryString(String query, int limit) throws Exception {
        Query q = new Query(query);
        return q.nSolutions(limit);
    }

    private int getScore(List<String> ds) {
        int acc = 0;
        for (int i = 0; i < ds.size(); i++) {
             acc += getScore(ds.get(i));
        }
        return acc;
    }

//    private String updateAbducibles(List<String> dSet, int mode, int count) {
//        StringJoiner sj = new StringJoiner(",");
//        for (String str : dSet) {
//            sj.add(str);
//            if (str.contains("ass(") && count == 1) {
//                abduced.add(str);
//            }
//        }
//
//        // only add abducibles that are cautiously entailed
//        for (String abd : abduced) {
//            if (!dSet.contains(abd)) {
//                abduced.remove(abd);
//                break;
//            }
//        }
//        return sj.toString();
//    }

    private List<String> convertToString(Term d) {
        List<String> dList = new ArrayList<>();
        if (d.isListPair()) {
            for (Term term : d.toTermArray()) {
                dList.add(term.toString());
            }
        }
        return dList;
    }

    private int getScore(String deltaString) {
        if (deltaString.contains("case")) {
            return 2;
        } else if (deltaString.contains("bg")) {
            return 1;
        }
        return 0;
    }

    public Result execute(String caseName, boolean all) throws Exception {
    abduced.clear();
    System.out.println(String.format("---------\nStart %s derivation", caseName));

        double time = System.nanoTime();
        loadFiles();
        Map<String, Term>[] maps = this.executeQuery(caseName, VERBOSE, all);
        Map<String, LinkedHashSet<List<String>>> resultMap = new HashMap<>();
        Map<String, Set<List<String>>> negMap = new HashMap<>();
        for (Map<String, Term> map : maps) {
            String culprit = map.get("X").name();

//            Set<List<String>> negDerivations = new HashSet<>();
//            Map<String, Term>[] ms =
//                executeQueryString(
//                    String.format("neg_goal(%s, %s, D)", caseName, culprit),3);
//            for (Map<String, Term> m: ms) {
//                Term d = m.get("D");
////                System.out.println("d...|" + d + "|");
//                if (!d.toString().equals("'FAIL'")) {
//                    negDerivations.add(convertToString(d));
//                } else {
//                    System.out.println("FAILED!");
//                }
//            }
//            negMap.put(culprit, negDerivations);

            LinkedHashSet<List<String>> set;
            if (resultMap.get(culprit) == null) {
                set = new LinkedHashSet<>();
                resultMap.put(culprit, set);
            } else {
                set = resultMap.get(culprit);
            }
            set.add(convertToString(map.get("D0")));
        }
        System.out.println("Results: " + resultMap);
        populateAbduced(resultMap);
        System.out.println("\nTotal time for " + caseName + ": " + ((System.nanoTime() - time)/pow(10, 9)) );
        String culpritString = culpritString(caseName, resultMap, negMap, getVisualTree().toArray());
        return new Result(culpritString, abduced, getPredMap(abduced, true));
    }

    private <E> Set<E> toSet(E[] list) {
        Set<E> set = new HashSet<>();
        for (E elem : list) {
            set.add(elem);
        }
        return set;
    }

    private void populateAbduced(Map<String, LinkedHashSet<List<String>>> resultMap) {
        boolean first = true;
        for (String culprit : resultMap.keySet()) {
            for (List<String> d : resultMap.get(culprit)) {
                for (String s : d) {
                    if (s.contains("ass(")) {
                        abduced.add(s);
                    }
                }
            }
        }
    }

    private void loadFiles() {
        try {
            executeQueryString(String.format(CONSULT_STRING, TECH), 1);
            executeQueryString(String.format(CONSULT_STRING, OP), 1);
            executeQueryString(String.format(CONSULT_STRING, STR), 1);
            executeQueryString(String.format(CONSULT_STRING, Utils.PROLOG_USER_EVIDENCE), 1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static Map<String, List<String>> getPredMap(Set<String> preds, boolean isAbducibles) {
        Map<String, List<String>> map = new HashMap<>();
        for (String pred : preds) {
            String key;
            if (isAbducibles) {
                key = pred.substring(4, pred.length() - 1).split("\\(")[0];
            } else {
                key = pred.split("\\(")[0];
            }
            List<String> val = new ArrayList<>();
            val.addAll(scanFileForPredicate(TECH, key));
            val.addAll(scanFileForPredicate(OP, key));
            val.addAll(scanFileForPredicate(STR, key));
            map.put(key, val);
        }
        return map;
    }

    private static List<String> scanFileForPredicate(String filename, String pred) {
        List<String> r = new ArrayList<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename + ".pl"));
            br.lines().forEach(line -> {
                if (line.contains(pred) && line.contains("rule(") && !line.contains("abducible(") && (line.charAt(0) != '%')) {
                    r.add(line);
                }
            });
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return r;
    }

    public static void main(String[] args) {

        try {
            QueryExecutor qe = QueryExecutor.getInstance();
            for (String c : new String[]{"apt1", "wannacryattack", "gaussattack", "stuxnetattack", "sonyhack", "usbankhack"}) {
                    System.out.println(qe.execute(c, false));
            }
            for (String c : new String[]{"dummy0", "dummy1", "dummy2", "dummy2b", "dummy3"}) {
                System.out.println(qe.execute(c, false));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
