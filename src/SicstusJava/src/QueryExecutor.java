import se.sics.jasper.*;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.*;

import static java.lang.Math.pow;

@SuppressWarnings("ALL")
public class QueryExecutor {
    private final boolean VERBOSE = false;
    private final boolean combined = false;

    private static final QueryExecutor instance = new QueryExecutor();
    // TODO: update to relative filepath of prolog files
    private static String FILEPATH = "";
    private static final String TECH = FILEPATH + "tech_rules.pl";
    private static final String OP = FILEPATH + "op_rules.pl";
    private static final String STR = FILEPATH + "str_rules.pl";
    private static final String TECHSAV = "tech.sav";
    private static final String OPSAV = "op.sav";
    private static final String STRSAV = "str.sav";

    private List<String[]> mapStrings = new ArrayList<>();
    private SICStus sp;
    private Map<String, Integer> techMap;
    private Map<String, Integer> opMap;
    private Map<String, Integer> strMap;
    private Map<String, List<String>> culprits;
    private Set<String> abduced;
    private Map<String, Set<Set<String>>> derivations;

    public static QueryExecutor getInstance() {
        return instance;
    }

    private QueryExecutor() {
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
        culprits = new HashMap<String, List<String>>();
        abduced = new HashSet<>();
        derivations = new HashMap<>();
        try {
            sp = new SICStus(new String[] {""},null);
            redefineFlagOff();
        } catch (SPException e) {
            e.printStackTrace();
        }

    }

    private void redefineFlagOff() throws SPException {
        SPPredicate pred = new SPPredicate(sp, "prolog_flag",  3, "");
        SPTerm redefineFlag = new SPTerm(sp, "redefine_warnings");
        SPTerm oldVal = new SPTerm(sp, "on");
        SPTerm newVal = new SPTerm(sp, "off");
        SPQuery query = sp.openQuery(pred,
                new SPTerm[]{redefineFlag, oldVal, newVal});
        query.nextSolution();
    }

    private String getVisualTree() {
        try {
            BufferedReader br = new BufferedReader(new FileReader("visual.log"));
            StringBuilder sb = new StringBuilder();
            br.lines().forEach(line -> sb.append(line + "\n"));
            return sb.toString();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void redirectStdout() {
        System.out.println("Redirecting stdout");
        try {
            SPQuery query = sp.openQuery(new SPPredicate(sp, "tell", 1, ""), new SPTerm[]{new SPTerm(sp,"sicstus_log.txt")});
            query.nextSolution();
        } catch (SPException e) {
            e.printStackTrace();
        }
    }

    private void closeRedirectStdout() {
        System.out.println("Closing redirected stdout");
        try {
            SPQuery query = sp.openQuery(new SPPredicate(sp, "told", 0, ""), new SPTerm[]{});
            query.nextSolution();
        } catch (SPException e) {
            e.printStackTrace();
        }
    }

    public String culpritString(String attack) {
        StringJoiner sj = new StringJoiner(",");
        for (String c : culprits.keySet()) {
            sj.add(String.format("%s [Score: %d, D: %d] Derivation: %s,\n", c, getScore(culprits.get(c), 2), derivations.get(c).size(), culprits.get(c)));
        }
        return "{" + attack + "}\n" + sj;
    }

    /*
    (mode)
    0 : tech
    1 : op
    2 : str
    */
    SPTerm[] executeQuery(int mode, String caseName, boolean verbose, boolean all) {
        SPQuery query;
        Map<String, Integer> accMap;
        int res;
        int numDeltas;
        Map<String, SPTerm> queryMap;
        String queryString;

        try
        {
            SPCanonicalAtom TIMEOUT = new SPCanonicalAtom(sp, "time_out");
            String goal;
            if (all) {
                goal = "goal_all";
            } else {
                goal = "goal";
            }

            if (combined) {
                accMap = strMap;
                sp.restore("all.sav");

                queryMap = new HashMap();
                queryString = String.format("goal_with_timeout(%s,X,D0,R).", goal, caseName);
                System.out.println(queryString);
                query = sp.openQuery(queryString, queryMap);
            } else {
                switch (mode) {
                    case 0:
                        numDeltas = 5;
                        System.out.println("Technical");
                        accMap = techMap;
                        sp.restore(TECHSAV);
                        sp.load(Utils.USER_EVIDENCE_FILENAME);

                        queryMap = new HashMap();
                        queryString = String.format("%s(%s,X,M,M1,M2,D0,D1,D2,D3,D4).", goal, caseName);
                        System.out.println(queryString);
                        query = sp.openQuery(queryString, queryMap);
                        break;
                    case 1:
                        numDeltas = 2;
                        System.out.println("Operational");
                        accMap = opMap;
                        sp.restore(OPSAV);
                        sp.load("tech.pl");
                        sp.load(Utils.USER_EVIDENCE_FILENAME);

                        queryMap = new HashMap();
                        queryString = String.format("%s(%s,X,X1,D0,D1).", goal, caseName);
                        System.out.println(queryString);
                        query = sp.openQuery(queryString, queryMap);
                        break;
                    case 2:
                        System.out.println("Strategic");
                        numDeltas = 1;
                        accMap = strMap;
                        sp.restore(STRSAV);
                        sp.load("tech.pl");
                        sp.load("op.pl");
                        sp.load(Utils.USER_EVIDENCE_FILENAME);

                        queryMap = new HashMap();
                        queryString = String.format("goal_with_timeout(%s,X,D0,R).", caseName);
                        query = sp.openQuery(queryString, queryMap);
                        System.out.println(queryString);
                        System.out.println(queryMap);
                        break;
                    default:
                        System.exit(-1);
                        return null;
                }
            }

            int count = 0;

            while (query.nextSolution() && count < 500) {
                if (queryMap.get("R") != null &&
                        TIMEOUT.toString().equals(queryMap.get("R").toString())) {
                    System.out.println("TIMEOUT");
                    continue;
                }
                count++;
                for (int i = 0; i < numDeltas; i++) {
                    SPTerm d = queryMap.get("D" + i);
                    SPTerm culprit = queryMap.get("X");

                    if (derivationIsSeen(d, culprit)) continue;

                    if (d.isList()) {
                        List<String> dList = new ArrayList<>();
                        for (SPTerm term : d.toTermArray()) {
                            dList.add(term.toString());
                        }
                        String ds = updateAbducibles(dList, mode, count);

                        if (verbose && queryMap.get("N") != null) {
                            System.out.println(String.format("Reliability: %s\n" +
                                    "Derivation: {%s}\n", queryMap.get("N"), ds));
                        }

                        String rulename = getRulename(mode, i, caseName, queryMap);

                        res = getScore(dList, mode);

                        if (accMap.get(rulename) == null || res > accMap.get(rulename)) {
                            accMap.put(rulename, res);
                        }
                        if (mode == 2) {
                            List<String> existingDerivation = culprits.get(culprit.toString());
                            int curr = existingDerivation == null ? 0 : getScore(existingDerivation, mode);
                            if (res > curr) {
                                dList.add("\nTree >" + getVisualTree() + "<");
                                culprits.put(culprit.toString(), dList);
                                System.out.println(culprits);
                            }
                        }
                    }
                }
            }

            SPTerm[] ret = new SPTerm[numDeltas];
            for (int i = 0; i < numDeltas; i++) {
                ret[i] = queryMap.get("D" + i);
            }
            return ret;
        } catch ( Exception e ) {
            e.printStackTrace();
            return null;
        }
    }

    private int getScore(List<String> ds, int mode) {
        int acc = 0;
        for (String d : ds) {
            acc += getScore(d, mode);
        }
        return acc;
    }

    private String updateAbducibles(List<String> dSet, int mode, int count) throws IllegalTermException, ConversionFailedException {
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
    private boolean derivationIsSeen(SPTerm d, SPTerm culprit) throws IllegalTermException, ConversionFailedException {
        Set<Set<String>> culpritSet = derivations.get(culprit.toString());

        if (culpritSet == null) {
            derivations.put(culprit.toString(), new HashSet<>());
            culpritSet = derivations.get(culprit.toString());
        }

        if (d.toString().charAt(0) == '_' || culpritSet.contains(toSet(d))) {
            return true;
        }

        culpritSet.add(toSet(d));
        return false;
    }

    private String getRulename(int mode, int i, String attack, Map<String, SPTerm> queryMap) {
        String label;
        String args;
        switch(mode) {
            case 0:
                label = "t";
                switch(i) {
                    case 0:
                    case 3:
                        args = attack.toString();
                        break;
                    case 1:
                        args = String.format("%s,%s", queryMap.get("X").toString(), attack.toString());
                        break;
                    case 2:
                        args = queryMap.get("M").toString();
                        break;
                    case 4:
                        args = String.format("%s,%s", queryMap.get("M1"), queryMap.get("M2"));
                        break;
                    default:
                        return "";
                }
                break;
            case 1:
                label = "op";
                if (i == 0) {
                    args = String.format("%s,%s", queryMap.get("X").toString(), attack.toString());
                } else {
                    args = String.format("%s,%s", queryMap.get("X1").toString(), attack.toString());
                }
                break;
            case 2:
                label = "str";
                args = attack.toString();
                break;
            default:
                return "";
        }
        return String.format("%s_%s(%s)", label, mapStrings.get(mode)[i], args);
    }

    private Set<String> toSet(SPTerm d) throws IllegalTermException, ConversionFailedException {
        if (!d.isList()) {
            return new HashSet<>();
        }
        Set<String> set = new HashSet<>();
        for (SPTerm term : d.toTermArray()) {
            set.add(term.toString());
        }
        return set;
    }

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
        if (deltaString.contains("case")) { // FIXME: add userevidence DONE: usercase also contains case
            acc += 2;
        } else if (deltaString.contains("bg")) {
            acc += 1;
        }
        return acc;
    }

//    private int getScore(List<String> delta, int mode) {
//        String deltaString = delta.toString();
//        return getScore(deltaString, mode);
//    }

    public Result execute(String caseName, boolean all) {
        culprits.clear();
        abduced.clear();
        derivations.clear();
        System.out.println(String.format("---------\nStart %s derivation", caseName));
        double time = System.nanoTime();
//        System.out.println("Start time: " + time);
        this.executeQuery(0, caseName, VERBOSE, all);
        double techTime = (System.nanoTime() - time)/pow(10,9);

        time = System.nanoTime();
//        System.out.println("Time taken for tech layer: " + techTime + "s");
        this.executeQuery(1, caseName, VERBOSE, all);
        double opTime = (System.nanoTime() - time)/pow(10,9);

        time = System.nanoTime();
//        System.out.println("Time taken for op layer: " + opTime + "s");
        SPTerm[] derivations = this.executeQuery(2, caseName, VERBOSE, all);
        double strTime = (System.nanoTime() - time)/pow(10,9);

//        System.out.println("Time taken for str layer: " + strTime + "s");
        System.out.println("\nTotal time for " + caseName + ": " + (techTime + opTime + strTime));

        return new Result(culpritString(caseName), techMap, opMap, strMap, abduced, getPredMap(abduced, true), derivations);
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
        for (String c : new String[]{"apt1", "wannacryattack", "gaussattack", "stuxnetattack", "sonyhack", "us_bank_hack"}) {
            System.out.println(qe.execute(c, false));
        }
//        System.out.println(qe.execute("gaussattack", false));
    }
}
