import org.jpl7.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.lang.Integer;
import java.util.*;

import static java.lang.Math.pow;
import static java.util.Collections.max;

//import se.sics.jasper.*;


@SuppressWarnings("ALL")
public class QueryExecutor {
    private static final String VISUALLOG = "visual.log";
    private final boolean VERBOSE = false;

    private static final QueryExecutor instance = new QueryExecutor();
    // TODO: update to relative filepath of prolog files
    private static String FILEPATH = "";
    private static final String CONSULT_STRING = "consult(%s)";
    private static final String TECH = FILEPATH + "tech_rules";
    private static final String OP = FILEPATH + "op_rules";
    private static final String STR = FILEPATH + "str_rules";
    private static final String TECHSAV = "tech.sav";
    private static final String OPSAV = "op.sav";
    private static final String STRSAV = "str.sav";

    private List<String[]> mapStrings = new ArrayList<>();
//    private SICStus sp;
    private Map<String, Integer> techMap;
    private Map<String, Integer> opMap;
    private Map<String, Integer> strMap;
    private Map<String, List<Integer>> culprits;
    private Map<Integer, List<String>> culpritsDerivation;
    private Set<String> abduced;

    public static QueryExecutor getInstance() {
        return instance;
    }

    private QueryExecutor() {
        JPL.init();
        mapStrings = new ArrayList<>();
        // tech
        mapStrings.add(new String[]{"requireHighResource", "culpritIsFrom", "notForBlackMarketUse", "specificTarget", "similar"});
        // operational
        mapStrings.add(new String[]{"hasCapability", "hasMotive", "governmentLinked"});
        // strategic
        mapStrings.add(new String[]{"isCulprit"});

        techMap = new HashMap<>();
        opMap = new HashMap<>();
        strMap = new HashMap<>();
        culprits = new HashMap<>();
        culpritsDerivation = new HashMap<>();
        abduced = new HashSet<>();
//        try {
//            sp = new SICStus(new String[] {""},null);
////            redefineFlagOff();
//        } catch (SPException e) {
//            e.printStackTrace();
//        }

    }

//    private void redefineFlagOff() throws SPException {
//        SPPredicate pred = new SPPredicate(sp, "prolog_flag",  3, "");
//        SPTerm redefineFlag = new SPTerm(sp, "redefine_warnings");
//        SPTerm oldVal = new SPTerm(sp, "on");
//        SPTerm newVal = new SPTerm(sp, "off");
//        SPQuery query = sp.openQuery(pred,
//                new SPTerm[]{redefineFlag, oldVal, newVal});
//        query.nextSolution();
//    }

    private String[] getVisualTree() {
        try {
            File f = new File(VISUALLOG);
            BufferedReader br = new BufferedReader(new FileReader(VISUALLOG));
            StringBuilder sb = new StringBuilder();
            br.lines().forEach(line -> {
                sb.append(line + "\n");
            });
            return sb.toString().split("\n\n\n");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void redirectStdout() {
//        try {
//            SPQuery query = sp.openQuery(String.format("tell('%s').", VISUALLOG), new HashMap());
//            query.nextSolution();
//        } catch (SPException e) {
//            e.printStackTrace();
//        }
    }

    private void closeRedirectStdout() {
//        try {
//            SPQuery query = sp.openQuery("told.", new HashMap());
//            query.nextSolution();
//        } catch (SPException e) {
//            e.printStackTrace();
//        }
    }

    public String culpritString(String attack, String[] visualTree) {
        StringJoiner sj = new StringJoiner(",");
        for (String c : culprits.keySet()) {
            List<Integer> scores = new ArrayList<>();
            for (int j : culprits.get(c)) {
                scores.add(getScore(culpritsDerivation.get(j), 2));
            }
            sj.add(String.format("%s [Highest score: %d, D: %d]\n", c,
                    max(scores),culprits.get(c).size()));
            for (int i = 0; i < culprits.get(c).size(); i++) {
                int num = culprits.get(c).get(i);
                StringJoiner trees = new StringJoiner("----");
                trees.add(visualTree[num-1]);
                sj.add(String.format("X = %s [Score: %d] \nDerivation:\n %s\n\n", c,
                    scores.get(i), trees));
            }
        }
        return "{" + attack + "}\n" + sj;
    }

    /*
    (mode)
    0 : tech
    1 : op
    2 : str
    */
    Map<String, Term>[] executeQuery(int mode, String caseName, boolean verbose, boolean all) {
//        Query query;
        Map<String, Integer> accMap;
        int res;
        int numDeltas;
        Map<String, Term>[] queryMap;
        String queryString;
        Set<String> queryStrings = new HashSet<>();

        try
        {
//            SPCanonicalAtom TIMEOUT = new SPCanonicalAtom(sp, "time_out");
            String goal;
            if (all) {
                goal = "goal_all";
            } else {
                goal = "goal";
            }

            if (mode < 0) {
                System.out.println("All");
                numDeltas = 1;
                accMap = strMap;

//                queryMap = new HashMap();
                queryString = String.format("goal(%s,X,D0)", caseName);
                queryMap = executeQueryString(queryString);
                System.out.println(queryString);
            } else {
                switch (mode) {
                    case 0:
                        numDeltas = 5;
                        System.out.println("Technical");
                        accMap = techMap;
                        executeQueryString(String.format(CONSULT_STRING, TECH));
                        executeQueryString(String.format(CONSULT_STRING, Utils.USER_EVIDENCE_FILENAME));

                        queryString = String.format("%s(%s,X,M,M1,M2,D0,D1,D2,D3,D4)", goal, caseName);
                        break;
                    case 1:
                        numDeltas = 2;
                        System.out.println("Operational");
                        accMap = opMap;
                        executeQueryString(String.format(CONSULT_STRING, OP));
                        executeQueryString(String.format(CONSULT_STRING, "tech"));
                        executeQueryString(String.format(CONSULT_STRING, Utils.USER_EVIDENCE_FILENAME));
                        queryString = String.format("%s(%s,X,X1,D0,D1)", goal, caseName);
                        break;
                    case 2:
                        System.out.println("Strategic");
                        numDeltas = 1;
                        accMap = strMap;
                        executeQueryString(String.format(CONSULT_STRING, STR));
                        executeQueryString(String.format(CONSULT_STRING, "tech"));
                        executeQueryString(String.format(CONSULT_STRING, "op"));
                        executeQueryString(String.format(CONSULT_STRING, Utils.USER_EVIDENCE_FILENAME));

                        queryString = String.format("goal(%s,X,D0)", caseName);

                        break;
                    default:
                        System.exit(-1);
                        return null;
                }
            }
            queryMap = executeQueryString(queryString);
            System.out.println(queryString);
            int count = 0;

            for (Map<String, Term> stringTermMap : queryMap) {
                System.out.println(stringTermMap);
            }

//            while (query.nextSolution() && count < 500) {
//                if (queryMap.get("R") != null &&
//                        TIMEOUT.toString().equals(queryMap.get("R").toString())) {
//                    System.out.println("TIMEOUT");
//                    continue;
//                }
//                count++;
//                for (int i = 0; i < numDeltas; i++) {
//                    SPTerm d = queryMap.get("D" + i);
//                    SPTerm culprit = queryMap.get("X");
//
//                    if (derivationIsSeen(d)) continue;
//
//                    if (d.isList()) {
//                        List<String> dList = convertToString(d);
//
//                        String ds = updateAbducibles(dList, mode, count);
//                        String rulename = getRulename(mode, i, caseName, queryMap);
//
//                        res = getScore(dList, mode);
//
//                        if (accMap.get(rulename) == null || res > accMap.get(rulename)) {
//                            accMap.put(rulename, res);
//                        }
//                        if (mode == 2 || mode < 0) {
//                            List<String> existingDerivation = culpritsDerivation.get(culprits.get(culprit.toString()));
//                            int curr = existingDerivation == null ? -1 : getScore(existingDerivation, mode);
//                            List list = culprits.get(culprit.toString());
//
//                            if (list == null) {
//                                list = new ArrayList<>();
//                                culprits.put(culprit.toString(), list);
//                            }
//
//                            list.add(count);
//                            culpritsDerivation.put(count, dList);
//                            queryStrings.add(String.format("time_out(prove([neg(isCulprit(%s,%s))],D), 500, R).",queryMap.get("X"), caseName));
//                        }
//                    }
//                }
//            }

//            for (String q : queryStrings) {
//                executeQueryString(q, new Term[]{new Atom("tech_rules")});
//            }

//            Term[] ret = new Term[numDeltas];
//            for (int i = 0; i < numDeltas; i++) {
//                ret[i] = queryMap.get("D" + i);
//            }

            return queryMap;
        } catch ( Exception e ) {
            e.printStackTrace();
            return null;
        }
    }

    private Map<String, Term>[] executeQueryString(String query) throws Exception {
        Query q = new Query(query);
        int limit = 10;
        return q.nSolutions(limit);
    }

//    private Map<String, Term>[] executeQueryString(String query, Term[] terms) throws Exception {
//        Query q = new Query(query, terms);
//        Map<String, Term>[] map = q.allSolutions();
//        return map;
//        while (q.hasMoreElements()) {
//            Hashtable binding = (Hashtable) q.nextElement();
//            Term t = (Term) binding.get(X);
//            System.out.println(t);
//        }
//        Map<String, SPTerm> negQueryMap = new HashMap<>();
//        Query q = sp.openQuery(query, negQueryMap);
//        int count = 0;
//        while (q.nextSolution() && count < 10) {
//            System.out.println(String.format("Negation derivation for %s: %s", query, negQueryMap.get("D")));
//            count++;
//        }
//    }

    private int getScore(List<String> ds, int mode) {
        int acc = 0;
        for (int i = 0; i < ds.size(); i++) {
             acc += getScore(ds.get(i), mode);
        }
        return acc;
    }

    private String updateAbducibles(List<String> dSet, int mode, int count) {
        StringJoiner sj = new StringJoiner(",");
        for (String str : dSet) {
            sj.add(str);
            if (str.contains("ass(") && count == 1) {
                abduced.add(str);
            }
        }

        // only add abducibles that are cautiously entailed
        for (String abd : abduced) {
            if (!dSet.contains(abd)) {
                abduced.remove(abd);
                break;
            }
        }
        return sj.toString();
    }

    /*
    * adds derivation to culpritSet
    * returns false if derivation starts with '_' (anonymous variable)
    * or if current derivation is seen
    */
//    private boolean derivationIsSeen(Term d) throws IllegalTermException, ConversionFailedException {
//        return culpritsDerivation.containsValue(convertToString(d));
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

//    private String getRulename(int mode, int i, String attack, Map<String, SPTerm> queryMap) {
//        String label;
//        String args;
//        switch(mode) {
//            case 0:
//                label = "t";
//                switch(i) {
//                    case 0:
//                    case 3:
//                        args = attack.toString();
//                        break;
//                    case 1:
//                        args = String.format("%s,%s", queryMap.get("X").toString(), attack.toString());
//                        break;
//                    case 2:
//                        args = queryMap.get("M").toString();
//                        break;
//                    case 4:
//                        args = String.format("%s,%s", queryMap.get("M1"), queryMap.get("M2"));
//                        break;
//                    default:
//                        return "";
//                }
//                break;
//            case 1:
//                label = "op";
//                if (i == 0) {
//                    args = String.format("%s,%s", queryMap.get("X").toString(), attack.toString());
//                } else {
//                    args = String.format("%s,%s", queryMap.get("X1").toString(), attack.toString());
//                }
//                break;
//            case 2:
//                label = "str";
//                args = attack.toString();
//                break;
//            default:
//                return "";
//        }
//        return String.format("%s_%s(%s)", label, mapStrings.get(mode)[i], args);
//    }

//    private Set<String> toSet(SPTerm d) throws IllegalTermException, ConversionFailedException {
//        if (!d.isList()) {
//            return new HashSet<>();
//        }
//        Set<String> set = new HashSet<>();
//        for (SPTerm term : d.toTermArray()) {
//            set.add(term.toString());
//        }
//        return set;
//    }

    private int getScore(String deltaString, int mode) {
        int acc = 0;
        String prefix;
        Map<String, Integer> map;
        if (mode != 0) {
            switch(mode) {
                case 1:
                    prefix = "t_";
                    map = techMap;
                    break;
                case 2:
                    prefix = "op_";
                    map = opMap;
                    break;
                default:
                    return 0;
            }
            if (deltaString.contains(prefix) && map.containsKey(deltaString)) {
                acc = map.get(deltaString);
            }
        }
        if (deltaString.contains("case")) {
            acc += 2;
        } else if (deltaString.contains("bg")) {
            acc += 1;
        }
        return acc;
    }

    public Result execute(String caseName, boolean all, boolean combined) {
        culprits.clear();
        culpritsDerivation.clear();
        abduced.clear();
        System.out.println(String.format("---------\nStart %s derivation", caseName));
        redirectStdout();

        if (combined) {
            double time = System.nanoTime();
            loadFiles();
            Map<String, Term>[] maps = this.executeQuery(-1, caseName, VERBOSE, all);
            Map<String, List<List<String>>> resultMap = new HashMap<>();
            for (Map<String, Term> map : maps) {
                String culprit = map.get("X").name();
                List<List<String>> list;
                if (resultMap.get(culprit) == null) {
                    list = new ArrayList<>();
                    resultMap.put(culprit, list);
                } else {
                    list = resultMap.get(culprit);
                }
                list.add(convertToString(map.get("D0")));
            }
            System.out.println("Results: " + resultMap);
            System.out.println("\nTotal time for " + caseName + ": " + ((System.nanoTime() - time)/pow(10, 9)) );

        } else {
            double time = System.nanoTime();
//        System.out.println("Start time: " + time);
            this.executeQuery(0, caseName, VERBOSE, all);
            double techTime = (System.nanoTime() - time) / pow(10, 9);

            time = System.nanoTime();
//        System.out.println("Time taken for tech layer: " + techTime + "s");
            this.executeQuery(1, caseName, VERBOSE, all);
            double opTime = (System.nanoTime() - time) / pow(10, 9);

            time = System.nanoTime();
//        System.out.println("Time taken for op layer: " + opTime + "s");
            this.executeQuery(2, caseName, VERBOSE, all);

            double strTime = (System.nanoTime() - time) / pow(10, 9);

//        System.out.println("Time taken for str layer: " + strTime + "s");
            System.out.println("\nTotal time for " + caseName + ": " + (techTime + opTime + strTime));
        }
        closeRedirectStdout();
        System.out.println(culprits);
        return new Result(culpritString(caseName, getVisualTree()), techMap, opMap, strMap, abduced, getPredMap(abduced, true));
    }

    private void loadFiles() {
        try {
            executeQueryString(String.format(CONSULT_STRING, TECH));
            executeQueryString(String.format(CONSULT_STRING, OP));
            executeQueryString(String.format(CONSULT_STRING, STR));
            executeQueryString(String.format(CONSULT_STRING, Utils.PROLOG_USER_EVIDENCE));
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
            BufferedReader br = new BufferedReader(new FileReader(filename));
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

        QueryExecutor qe = QueryExecutor.getInstance();
//        try {
//            System.out.println(qe.executeQueryString("consult(tech_rules)")[0]);
//            System.out.println(qe.executeQueryString("prove([targetCountry(X, dummy3)],D)")[0]);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
        for (String c : new String[]{"apt1", "wannacryattack", "gaussattack", "stuxnetattack", "sonyhack", "usbankhack"}) {
            System.out.println(qe.execute(c, false, true));
        }
//        for (String c : new String[]{"dummy0", "dummy1", "dummy2", "dummy2b", "dummy3"}) {
//            System.out.println(qe.execute(c, false, true));
//        }

    }
}
