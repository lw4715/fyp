import javafx.util.Pair;
import org.jpl7.JPL;
import org.jpl7.PrologException;
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
    static final String ALPHANUMERIC = "[A-Za-z0-9_]";
    List<Double> timings;
    private boolean verbose = false;
    private ToolIntegration ti;

    private static final QueryExecutor instance = new QueryExecutor();
    private static final String CONSULT_STRING = "consult('%s')";


    private Set<String> abduced;
    private ArrayList<String> allFiles;

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
    }

    // after executing query, call this method to get argumentation trees
    private LinkedHashSet<String> extractArgumentationTreeFromFile() {
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

    // execute query with limit
    private Map<String, Term>[] executeQueryString(String query, int limit) throws Exception {
        if (verbose) System.out.println(query);
        Query q = new Query(query);
        try {
            return q.nSolutions(limit);
        } catch (PrologException e) {
            return new Map[0];
        }
    }

    // format output from executeQueryString
    private String formatQueryOutput(Map<String, Term>[] output) {
        StringBuilder sb = new StringBuilder();

        Set<Map<String, Term>> set = new HashSet<>();
        Collections.addAll(set, output);

        for (Map<String, Term> stringTermMap : set) {
            for (String term : stringTermMap.keySet()) {
                Term d = stringTermMap.get(term);
                sb.append(term + "=" + convertToString(d) + "\n");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    String executeCustomQuery(String queryList) {
        String query = String.format("prove([%s], D)", queryList);
        System.out.println("Executing custom query: " + query);
        try {
            loadFiles();
            return formatQueryOutput(executeQueryString(query, 20));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
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

    // prove all predicates
    public Result executeAll(String caseName, List<String> culpritsList) {
        System.out.println("Executing for " + caseName);
        abduced.clear();
        Map<String, Term>[] maps = this.executeQuery(caseName, verbose, true, culpritsList);
        return null;
    }

    // prove([isCulprit(X, caseName)], D)
    public Result execute(String caseName, boolean reload, List<String> culpritsList) throws Exception {
        System.out.println("Executing for " + caseName);
        loadFiles();
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
        Result r = new Result(caseName, resultMap, extractArgumentationTreeFromFile().toArray(),
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

    private void clearLeftoverFiles() {
        Utils.clearFile(Utils.USER_EVIDENCE_FILENAME);
        Utils.clearFile(ToolIntegration.AUTOMATED_GEOLOCATION_PL);
        Utils.clearFile(ToolIntegration.TOR_IP_FILE);
        Utils.clearFile(ToolIntegration.VIRUS_TOTAL_PROLOG_FILE);
    }

    private void loadFiles() {
        allFiles = new ArrayList<>();
        allFiles.add("utils.pl");
        allFiles.add("evidence.pl");
        allFiles.add(Utils.USER_EVIDENCE_FILENAME);
        ti.preprocessFiles(allFiles);

        try {
            executeQueryString(String.format(CONSULT_STRING, "utils.pl"), 1);
            executeQueryString(String.format(CONSULT_STRING, Utils.TECH), 1);
            executeQueryString(String.format(CONSULT_STRING, Utils.OP), 1);
            executeQueryString(String.format(CONSULT_STRING, Utils.STR), 1);

            ti.torIntegration();
            executeQueryString(String.format(CONSULT_STRING, Utils.USER_EVIDENCE_FILENAME), 1);
            executeQueryString(String.format(CONSULT_STRING, ToolIntegration.TOR_IP_FILE), 1);
            executeQueryString(String.format(CONSULT_STRING, ToolIntegration.AUTOMATED_GEOLOCATION_PL), 1);
            executeQueryString(String.format(CONSULT_STRING, ToolIntegration.VIRUS_TOTAL_PROLOG_FILE), 1);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    // return rules corresponding to predicates
    static Map<String, List<String>> getPredMap(Collection<String> preds, boolean isAbducibles) {
        Map<String, List<String>> map = new HashMap<>();
        for (String pred : preds) {
            String key;
            if (isAbducibles) {
                key = pred.substring(4, pred.length() - 1).split("\\(")[0];
            } else {
                key = pred.substring(0, pred.lastIndexOf("("));
            }
            List<String> val = new ArrayList<>();
            val.addAll(Utils.scanFileForPredicate(Utils.TECH, key));
            val.addAll(Utils.scanFileForPredicate(Utils.OP, key));
            val.addAll(Utils.scanFileForPredicate(Utils.STR, key));
            map.put(key, val);
        }
        return map;
    }

    static List<String> getConflictingRule(String posDer, String negDer) {
        List<String> l = new ArrayList<>();
        char placeholder = '$';
        posDer = posDer + placeholder;
        negDer = negDer + placeholder;
        String[] posRules = posDer.replaceFirst("\\[", "").replace("]" + placeholder, "").split("\\)");
        String[] negRules = negDer.replaceFirst("\\[", "").replace("]" + placeholder, "").split("\\)");

        String posStrRule = Utils.removeLeadingNonAlpha(posRules[posRules.length - 1]) + ")";
        String negStrRule = Utils.removeLeadingNonAlpha(negRules[negRules.length - 1]) + ")";

        for (String pr : posRules) {
            String prTrimmed = pr.trim();
            if (prTrimmed.contains(Utils.R_STR_)) {
                prTrimmed = prTrimmed.substring(prTrimmed.indexOf(Utils.R_STR_), prTrimmed.length());
                posStrRule = prTrimmed + ")";
            }
        }
        l.add(posStrRule);

        for (String nr : negRules) {
            String nrTrimmed = nr.trim();
            if (nrTrimmed.contains(Utils.R_STR_)) {
                nrTrimmed = nrTrimmed.substring(nrTrimmed.indexOf(Utils.R_STR_), nrTrimmed.length());
                negStrRule = nrTrimmed + ")";
            }
        }
        l.add(negStrRule);
        return l;
    }

    private void setDebug() {
        verbose = true;
    }

        // try to prove given gorgiasRule, return pair containing proved predicates (key) and not proved predicates (value)
    public static Pair<List<String>, List<String>> tryToProve(String gorgiasRule, String attackName, String givenHead) throws Exception {
        Map<String, String> argMap = new HashMap<>();
        String head = Utils.getHeadOfLine(gorgiasRule);
        if (givenHead.length() > 0) {
            if (givenHead.startsWith("neg(")) {
                givenHead = givenHead.split("neg\\(")[1];
            }
            String headConstantsAll = Utils.regexMatch("\\(.*\\)", givenHead).get(0);
            List<String> headConstants = Utils.regexMatch("\\b[a-z]" + ALPHANUMERIC + "*\\b", headConstantsAll);

            String headVarAll = Utils.regexMatch("\\(.*\\)", head).get(0);
            List<String> headVar = Utils.regexMatch("\\b[A-Z]" + ALPHANUMERIC + "*\\b", headVarAll);

            for (int i = 0; i < headConstants.size(); i++) {
                String var = headVar.get(i);
                String constant = headConstants.get(i);
                argMap.put(var, constant);
            }
        }

        List proved = new ArrayList<>();
        List notProved = new ArrayList<>();
        Pair<List<String>, List<String>> ret = new Pair<>(proved, notProved);

        Map<String, String> args = new HashMap<>();
        String body = Utils.getBodyOfLine(gorgiasRule);
        String[] bs = body.split("\\)");
        List<String> bsList = new ArrayList<>();
        Collections.addAll(bsList, bs);

        if (bsList.size() == 0) return ret;

//        String b = bsList.get(0);
//        int i = 0;
        for (String b : bsList) {
            if (b.length() > 0) {
                b = Utils.removeLeadingNonAlpha(b);

                // add missing ")" to match "("
                int openCount = (int) b.chars().filter(c -> c == '(').count();
                b = b + String.join("", Collections.nCopies(openCount, ")"));

                // replace attack var
                List<String> s = Utils.regexMatch("\\(.*\\)", b);
                String formattedB = b.replaceAll("\\bAtt\\b", attackName).replaceAll("\\bA1\\b", attackName).replaceAll("\\bA\\b", attackName);

                if (s.size() > 0) {
                    String allVars = s.get(0);
                    List<String> vars = Utils.regexMatch("\\b[A-Z]" + ALPHANUMERIC + "*\\b", allVars);
                    for (String var : vars) {
                        if (argMap.containsKey(var)) {
                            formattedB = formattedB.replaceAll("\\b" + var + "\\b", argMap.get(var));
                        }
                    }
                }

                String q = String.format("prove([%s], D)", formattedB);
                Map<String, Term>[] m = getInstance().executeQueryString(q, 10);

                List<String> s1 = Utils.regexMatch("\\(.*\\)", formattedB);
                if (s1.size() > 0) {
                    String allVarsAfter = s1.get(0);
                    List<String> varsAfter = Utils.regexMatch("\\b[A-Z]" + ALPHANUMERIC + "*\\b", allVarsAfter);
                    if (m.length > 0) {
                        for (String var : varsAfter) {
                            var = var.trim();
//                            String constant = m[0].get(var).name(); //FIXME
                            for (Map<String, Term> stringTermMap : m) {
                                String constant = stringTermMap.get(var).name();
                                if (!constant.equals("[|]")) {
                                    argMap.put(var, constant);
                                }
                                formattedB = formattedB.replaceAll("\\b" + var + "\\b", constant);
                                if (!proved.contains(formattedB)) {
                                    proved.add(formattedB);
                                }
                            }
                        }
                    } else {
                        notProved.add(formattedB);
                    }
                }
            }
//            i++;
        }
        return ret;
    }

    //returns Pair<(proved), (not proved)>
    static Pair<List<String>, List<String>> tryToProve(String gorgiasRule, String attackName) throws Exception {
        return tryToProve(gorgiasRule, attackName, "");
    }

    public static void main(String[] args) {
        QueryExecutor qe = QueryExecutor.getInstance();
        qe.setDebug();
        int n = 1;
        try {
            qe.clearLeftoverFiles();

            for (int i = 0; i < n; i++) {
//                for (String c : new String[]{"apt1", "wannacryattack", "gaussattack", "stuxnetattack", "sonyhack", "usbankhack"}) {
//                    Result r = qe.execute(c, false, new ArrayList<>());
//                    System.out.println(r);
//                }
                for (String c : new String[]{"example0", "example1", "example2", "example2b", "example3", "example4", "example5"}) {
                    Result r = qe.execute(c, false, new ArrayList<>());
                    System.out.println(r);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        assert (n == qe.timings.size());
        System.out.println("Mean total runtime over " + n + " times: " + Utils.mean(qe.timings));

    }


}
