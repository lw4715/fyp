import javafx.util.Pair;
import org.jpl7.JPL;
import org.jpl7.Query;
import org.jpl7.Term;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.*;

import static java.lang.Math.pow;


@SuppressWarnings("ALL")
public class QueryExecutor {
    List<Double> timings;
    private boolean verbose = false;
    private ToolIntegration ti;

    private static final QueryExecutor instance = new QueryExecutor();
    private static final String CONSULT_STRING = "consult('%s')";


    private Set<String> abduced;
    private ArrayList<String> allFiles;
    private ArrayList<String> reloadFiles;

    public static QueryExecutor getInstance() {
        return instance;
    }

    private QueryExecutor() {
        JPL.init();
        timings = new ArrayList<>();
        abduced = new HashSet<>();
        ti = new ToolIntegration();
        clearLeftoverFiles();
        loadFiles();
        reloadFiles = new ArrayList<>();
        reloadFiles.add(Utils.USER_EVIDENCE_FILENAME);
        reloadFiles.add(ToolIntegration.SQUID_LOG_RULES_PL);
    }

    private LinkedHashSet<String> getVisualTree() {
        try {
            File f = new File(Utils.VISUALLOG);
            BufferedReader br = new BufferedReader(new FileReader(Utils.VISUALLOG));
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
            System.out.println("Size of visual tree=" + set.size());
            return set;
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    Map<String, Term>[] executeQuery(String caseName, boolean verbose, boolean all, List<String> culpritsList) {
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
                // tech
                queryString = String.format("goal_all(%s,X, M, M2, M3, D1, D2, D3, D4, D5)", caseName);
                System.out.println(queryString);
                executeQueryString(queryString, 200);

                // op
                if (!culpritsList.isEmpty()) {
                    for (String c : culpritsList) {
                        String s = String.format("hasCapability(%s,%s, D)", c, caseName);
                        String s1 = String.format("hasCapability(%s,%s)", c, caseName);
                        executeQueryString(String.format("%s;(\\+ %s, writeNonResultsToFile(%s))", s, s, s1), 20);
                        s = String.format("hasMotive(%s,%s, D)", c, caseName);
                        s1 = String.format("hasMotive(%s,%s)", c, caseName);
                        executeQueryString(String.format("%s;(\\+ %s, writeNonResultsToFile(%s))", s, s, s1), 20);
                    }
                }
                queryString = String.format("goal_all(%s, X1, D1, D2, D3, D4, D5)", caseName);
                System.out.println(queryString);
                executeQueryString(queryString, 200);

                queryString = String.format("goal_all(%s, X, D)", caseName);
                System.out.println(queryString);
                executeQueryString(queryString, 50);

            } else {
                executeQueryString(String.format("tell('%s')", Utils.VISUALLOG), 1);
                queryString = String.format("goal(%s,X,D0)", caseName);
                queryMap = executeQueryString(queryString, 10);
                System.out.println(queryString);
                executeQueryString("told", 1);
                return queryMap;
            }
        } catch ( Exception e ) {
            e.printStackTrace();
            return null;
        }
        return new Map[0];
    }

    private Map<String, Term>[] executeQueryString(String query, int limit) throws Exception {
        if (verbose) System.out.println(query);
        Query q = new Query(query);
        return q.nSolutions(limit);
    }

    private String formatQueryOutput(Map<String, Term>[] output) {
        StringBuilder sb = new StringBuilder();
        for (Map<String, Term> stringTermMap : output) {
            for (String term : stringTermMap.keySet()) {
                Term d = stringTermMap.get(term);
                sb.append(term + "=" + convertToString(d) + "\n");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    static String executeCustomQuery(String query) {
        System.out.println("Executing custom query: " + query);
        try {
            QueryExecutor qe = getInstance();
            qe.loadFiles();
            return qe.formatQueryOutput(qe.executeQueryString(query, 20));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    static int getScore(List<String> ds) {
        int acc = 0;
        for (int i = 0; i < ds.size(); i++) {
             acc += getScore(ds.get(i));
        }
        return acc;
    }

    private List<String> convertToString(Term d) {
        List<String> dList = new ArrayList<>();
        if (d.isListPair()) {
            for (Term term : d.toTermArray()) {
                if (term.arity() == 0) {
                    dList.add(term.toString() + "()");
                } else {
                    dList.add(term.toString());
                }
            }
        } else {
            dList.add(d.toString());
        }
        return dList;
    }


    private static int getScore(String deltaString) {
        if (deltaString.contains("case")) {
            return 2;
        } else if (deltaString.contains("bg")) {
            return 1;
        }
        return 0;
    }


    public Result executeAll(String caseName, List<String> culpritsList) {
        System.out.println("Executing for " + caseName);
        reloadUserFile();
        abduced.clear();
        Map<String, Term>[] maps = this.executeQuery(caseName, verbose, true, culpritsList);
        return null;
    }

    public Result execute(String caseName, boolean reload, List<String> culpritsList) throws Exception {
        System.out.println("Executing for " + caseName);
//        if (reload)
        reloadUserFile();

        abduced.clear();
        System.out.println(String.format("---------\nStart %s derivation", caseName));

        double time = System.nanoTime();
        int count = 0;
        Map<String, Term>[] maps = this.executeQuery(caseName, verbose, false, culpritsList);
        Map<String, LinkedHashSet<List<String>>> resultMap = new HashMap<>();
        Map<String, Set<List<String>>> negMap = new HashMap<>();
        Set<String> culprits = new HashSet<>();

        for (Map<String, Term> map : maps) {
            String culprit = map.get("X").name();

            LinkedHashSet<List<String>> set;
            if (resultMap.get(culprit) == null) {
                set = new LinkedHashSet<>();
                resultMap.put(culprit, set);
            } else {
                set = resultMap.get(culprit);
            }

            Term t = map.get("D0");

            if (!t.toString().equals("'FAIL'")) {
                culprits.add(culprit);
                List<String> d = convertToString(t);
                set.add(d);
                DerivationNode.createDerivationAndSaveDiagram(t, caseName, count);
                count++;
            }
        }

        for (String culprit : culprits) {
            Set<List<String>> negDerivations = new HashSet<>();
            String negQueryString = String.format("prove([neg(isCulprit(%s, %s))], D)", culprit, caseName);
            Map<String, Term>[] ms =
                executeQueryString(
                    negQueryString, 5);
            for (Map<String, Term> m: ms) {
                Term d = m.get("D");
                if (verbose) System.out.println(ms + " " + m);
                if (!d.toString().equals("'FAIL'")) {
                    negDerivations.add(convertToString(d));
                } else {
                    System.out.println("FAILED!");
                }
            }
            if (!negDerivations.isEmpty()) {
                negMap.put(culprit, negDerivations);
            }
        }

        populateAbduced(resultMap);
        time = ((System.nanoTime() - time)/pow(10, 9));
        timings.add(time);
        System.out.println("\nTotal time for " + caseName + ": " + time );
        Result r = new Result(caseName, resultMap, getVisualTree().toArray(),
                abduced, getPredMap(abduced, true), negMap);
        if (verbose) {
            for (Pair<String, Pair<List<String>, String>> s : r.resultStrings()) {
                System.out.println(s.getKey());
            }
            for (String neg : r.negDerivationFor(culprits.toArray()[0].toString())) {
                System.out.println(neg);
            }
        }

        return r;
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

    private void reloadUserFile() {
        try {
            ti.preprocessFiles(reloadFiles);
            executeQueryString(String.format(CONSULT_STRING, ToolIntegration.SQUID_LOG_RULES_PL), 1);
            executeQueryString(String.format(CONSULT_STRING, Utils.USER_EVIDENCE_FILENAME), 1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void clearLeftoverFiles() {
        Utils.clearFile(Utils.USER_EVIDENCE_FILENAME);
        Utils.clearFile(ToolIntegration.SQUID_LOG_RULES_PL);
        Utils.clearFile(ToolIntegration.AUTOMATED_GEOLOCATION_PL);
        Utils.clearFile(ToolIntegration.TOR_IP_FILE);
        Utils.clearFile(ToolIntegration.VIRUS_TOTAL_PROLOG_FILE);
    }

    private void loadFiles() {
        allFiles = new ArrayList<>();
        allFiles.add("utils.pl");
        allFiles.add("evidence.pl");
        allFiles.add(Utils.USER_EVIDENCE_FILENAME);
        allFiles.add(ToolIntegration.SQUID_LOG_RULES_PL);
        ti.preprocessFiles(allFiles);

        try {
            executeQueryString(String.format(CONSULT_STRING, "utils.pl"), 1);
            executeQueryString(String.format(CONSULT_STRING, Utils.TECH), 1);
            executeQueryString(String.format(CONSULT_STRING, Utils.OP), 1);
            executeQueryString(String.format(CONSULT_STRING, Utils.STR), 1);

            ti.torIntegration();
            executeQueryString(String.format(CONSULT_STRING, Utils.USER_EVIDENCE_FILENAME), 1);
            executeQueryString(String.format(CONSULT_STRING, ToolIntegration.TOR_IP_FILE), 1);
            executeQueryString(String.format(CONSULT_STRING, ToolIntegration.SQUID_LOG_RULES_PL), 1);
            executeQueryString(String.format(CONSULT_STRING, ToolIntegration.AUTOMATED_GEOLOCATION_PL), 1);
            executeQueryString(String.format(CONSULT_STRING, ToolIntegration.VIRUS_TOTAL_PROLOG_FILE), 1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    static Map<String, List<String>> getPredMap(Collection<String> preds, boolean isAbducibles) {
        Map<String, List<String>> map = new HashMap<>();
        for (String pred : preds) {
            String key;
            if (isAbducibles) {
                key = pred.substring(4, pred.length() - 1).split("\\(")[0];
            } else {
                key = pred.substring(0, pred.lastIndexOf("("));
//                key = pred.split("\\(")[0];
            }
            List<String> val = new ArrayList<>();
            val.addAll(scanFileForPredicate(Utils.TECH, key));
            val.addAll(scanFileForPredicate(Utils.OP, key));
            val.addAll(scanFileForPredicate(Utils.STR, key));
            map.put(key, val);
        }
        return map;
    }

    private static List<String> scanFileForPredicate(String filename, String pred) {
        List<String> r = new ArrayList<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            br.lines().forEach(line -> {
                if (line.contains(pred) && line.contains("rule(") && !line.contains("abducible(") && (line.charAt(0) != '%')) {
                    r.add(line.replace("\t",""));
                }
            });
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return r;
    }

    static List<String> getConflictingRule(String posDer, String negDer) {
        List<String> l = new ArrayList<>();
        posDer = posDer + "$";
        negDer = negDer + "$";
        String[] posRules = posDer.replaceFirst("\\[", "").replace("\\]$", "").split("\\)");
        String[] negRules = negDer.replaceFirst("\\[", "").replace("\\]$", "").split("\\)");

        String posStrRule = null;
        String negStrRule = null;

        for (String pr : posRules) {
            String prTrimmed = pr.trim();
            if (prTrimmed.contains("r_str_")) {
                prTrimmed = prTrimmed.substring(prTrimmed.indexOf("r_str_"), prTrimmed.length());
                posStrRule = prTrimmed + ")";
            }
        }
        l.add(posStrRule);

        for (String nr : negRules) {
            String nrTrimmed = nr.trim();
            if (nrTrimmed.contains("r_str_")) {
                nrTrimmed = nrTrimmed.substring(nrTrimmed.indexOf("r_str_"), nrTrimmed.length());
                negStrRule = nrTrimmed + ")";
            }
        }
        l.add(negStrRule);
        return l;
    }

    private static double mean(List<Double> timings) {
        double acc = 0;
        for (Double t : timings) {
            acc += t;
        }
        return acc/timings.size();
    }

    private void setDebug() {
        verbose = true;
    }

    public static void main(String[] args) {
//        getConflictingRule("[r_op_notTargetted(example2b), case_example2b_f2b(), case_example2b_f2(), ass(notForBlackMarketUse(example2b_m2)), ass(notForBlackMarketUse(example2b_m1)), case_example2b_f5(), case_example2b_f4(), r_t_similar1(example2b_m1, example2b_m2), case_example2b_f3(), r_str_linkedMalware(yourCountry, example2b)]",
//                "[case_example2b_f2(),r_str_targetItself2(yourCountry, example2b)]");

        QueryExecutor qe = QueryExecutor.getInstance();
//        qe.setDebug();
        int n = 1;
        try {
//            System.out.println(qe.execute("example5", false));
            DerivationNode.createDiagram("img/_sample.svg", DerivationNode.getExampleNode(), new ArrayList<>());

            for (int i = 0; i < n; i++) {
                for (String c : new String[]{"apt1", "wannacryattack", "gaussattack", "stuxnetattack", "sonyhack", "usbankhack"}) {
                    Result r = qe.execute(c, false, new ArrayList<>());
                    System.out.println(r);
                }
                for (String c : new String[]{"example0", "example1", "example2", "example2b", "example3", "example4", "example5"}) {
                    Result r = qe.execute(c, false, new ArrayList<>());
                    System.out.println(r);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        assert (n == qe.timings.size());
        System.out.println("Mean total runtime over " + n + " times: " + mean(qe.timings));

    }

}
