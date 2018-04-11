import se.sics.jasper.*;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.*;

import static java.lang.Math.pow;

@SuppressWarnings("ALL")
public class QueryExecutor {
    private final boolean VERBOSE = true;

    private static final QueryExecutor instance = new QueryExecutor();
    // TODO: update to relative filepath of prolog files
    private static String FILEPATH = "";
    private static final String TECH = FILEPATH + "tech_rules.pl";
    private static final String OP = FILEPATH + "op_rules.pl";
    private static final String STR = FILEPATH + "str_rules.pl";

    private List<String[]> mapStrings = new ArrayList<>();
    private SICStus sp;
    private Map<String, Integer> techMap;
    private Map<String, Integer> opMap;
    private Map<String, Integer> strMap;
    private Map<String, Integer> culprits;
    private Set<String> abduced;
    private Map<String, Set<Set<String>>> derivations;

    public static QueryExecutor getInstance() {
        return instance;
    }

    private QueryExecutor() {
        mapStrings = new ArrayList<>();
        // tech
        mapStrings.add(new String[]{"requireHighResource", "culpritIsFrom", "notForBlackMarketUse", "specificTarget", "similar"});
        // op
        mapStrings.add(new String[]{"hasCapability", "hasMotive", "governmentLinked"});
        mapStrings.add(new String[]{"isCulprit"});

        techMap = new HashMap<>();
        opMap = new HashMap<>();
        strMap = new HashMap<>();
        culprits = new HashMap<>();
        abduced = new HashSet<>();
        derivations = new HashMap<>();
        try {
            sp = new SICStus(new String[] {""},null);
            SPPredicate pred = new SPPredicate(sp, "prolog_flag",  3, "");
            SPTerm redefineFlag = new SPTerm(sp, "redefine_warnings");
            SPTerm oldVal = new SPTerm(sp, "on");
            SPTerm newVal = new SPTerm(sp, "off");
            SPQuery query = sp.openQuery(pred,
                    new SPTerm[]{redefineFlag, oldVal, newVal});
            query.nextSolution();
        } catch (SPException e) {
            e.printStackTrace();
        }

    }

    public String culpritString() {
        StringBuilder sb = new StringBuilder();
        for (String c : culprits.keySet()) {
            sb.append(String.format("%s [Score: %d, D: %d], ", c, culprits.get(c), derivations.get(c).size()));
        }
        return sb.toString();
    }

    /*
    (mode)
    0 : tech
    1 : op
    2 : str
    */
    void executeQuery(int mode, String caseName, boolean verbose, boolean all) {
        SPPredicate pred;
        SPTerm attack, culprit, r, m = null, m1 = null, m2 = null, person = null;
        SPQuery query;
        Map<String, Integer> accMap;
        int res;
        int numDeltas;

        try
        {
            SPCanonicalAtom TIMEOUT = new SPCanonicalAtom(sp, "time_out");
            r = new SPTerm(sp, "success");
            SPTerm[] ds;
            String goal;
            if (all) {
                goal = "goal_all";
            } else {
                goal = "goal";
            }

            switch(mode) {
                case 0:
                    numDeltas = 5;
                    System.out.println("\n-------\nTECHNICAL");
                    accMap = techMap;
                    sp.restore("tech.sav");
                    sp.load(Utils.USER_EVIDENCE_FILENAME);
                    pred = new SPPredicate(sp, goal, numDeltas + 5, "");
                    attack = new SPTerm(sp, caseName);
                    culprit = new SPTerm(sp).putVariable();
                    m = new SPTerm(sp).putVariable();
                    m1 = new SPTerm(sp).putVariable();
                    m2 = new SPTerm(sp).putVariable();
                    ds = new SPTerm[numDeltas];
                    for (int i = 0; i < numDeltas; i++) {
                        ds[i] = new SPTerm(sp).putVariable();
                    }
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, m, m1, m2, ds[0], ds[1], ds[2], ds[3], ds[4] });
                    break;
                case 1:
                    numDeltas = 3;
                    System.out.println("\n-------\nOPERATIONAL");
                    accMap = opMap;
                    sp.restore("op.sav");
                    sp.load(Utils.USER_EVIDENCE_FILENAME);
                    pred = new SPPredicate(sp, goal, numDeltas + 3, "");
                    attack = new SPTerm(sp, caseName);
                    culprit = new SPTerm(sp).putVariable();
                    person = new SPTerm(sp).putVariable();
                    ds = new SPTerm[numDeltas];
                    for (int i = 0; i < numDeltas; i++) {
                        ds[i] = new SPTerm(sp).putVariable();
                    }
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, person, ds[0], ds[1], ds[2] });
                    break;
                case 2:
                    System.out.println("\n-------\nSTRATEGIC");
                    accMap = strMap;
                    sp.restore("str.sav");
                    sp.load(Utils.USER_EVIDENCE_FILENAME);
                    pred = new SPPredicate(sp, "goal_with_timeout", 4, "");
                    attack = new SPTerm(sp, caseName);
                    culprit = new SPTerm(sp).putVariable();
                    ds = new SPTerm[1];
                    ds[0] = new SPTerm(sp).putVariable();
                    r = new SPTerm(sp).putVariable();
                    query = sp.openQuery(pred, new SPTerm[] {attack, culprit, ds[0], r});
                    break;
                default:
                    System.exit(-1);
                    return;
            }

            int count = 0;

            while (query.nextSolution() && count < 75) {
                if (TIMEOUT.toString().equals(r.toString())) {
                    System.out.println("TIMEOUT");
                    continue;
                }
                count++;
                for (int i = 0; i < ds.length; i++) {
                    SPTerm d = ds[i];

                    if (derivationIsSeen(d, culprit)) continue;

                    if (d.isList()) {
                        res = 0;
                        Set<String> dSet = new HashSet<>();
                        for (SPTerm term : d.toTermArray()) {
                            dSet.add(term.toString());
                        }
                        StringBuilder sb = new StringBuilder("{");
                        for (String str : dSet) {
                            sb.append(str + ",");
                            res += getScore(str, mode);
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

                        if (verbose) System.out.println(sb + "}");

                        String rulename = getRulename(mode, i, attack, culprit, person, m, m1, m2);

                        if (accMap.get(rulename) == null || res > accMap.get(rulename)) {
                            accMap.put(rulename, res);
                        }
                        if (mode == 2 && caseName.equals(attack.toString())) {
                            Integer curr = culprits.get(culprit.toString());
                            if (curr == null || res > curr) {
                                culprits.put(culprit.toString(), res);
                                System.out.println(culprits);
                            }
                        }
                    }
                }
            }

            System.out.println("Finished\n");
            return;
        } catch ( Exception e ) {
            e.printStackTrace();
            return;
        }
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

    private String getRulename(int mode, int i, SPTerm attack, SPTerm culprit, SPTerm person, SPTerm m, SPTerm m1, SPTerm m2) {
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
                        args = String.format("%s,%s", culprit.toString(), attack.toString());
                        break;
                    case 2:
                        args = m.toString();
                        break;
                    case 4:
                        args = String.format("%s,%s", m1.toString(), m2.toString());
                        break;
                    default:
                        return "";
                }
                break;
            case 1:
                label = "op";
                if (i == 2) {
                    args = String.format("%s,%s", person.toString(), attack.toString());
                } else {
                    args = String.format("%s,%s", culprit.toString(), attack.toString());
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

    private int getScore(SPTerm delta, int mode) {
        String deltaString = delta.toString();
        return getScore(deltaString, mode);
    }

    public Result execute(String caseName, boolean all) {
        culprits.clear();
        abduced.clear();
        derivations.clear();

        double time = System.nanoTime();
        System.out.println("Start time: " + time);
        this.executeQuery(0, caseName, VERBOSE, all);
        double techTime = (System.nanoTime() - time)/pow(10,9);

        time = System.nanoTime();
        System.out.println("Time taken for tech layer: " + techTime + "s");
        this.executeQuery(1, caseName, VERBOSE, all);
        double opTime = (System.nanoTime() - time)/pow(10,9);

        time = System.nanoTime();
        System.out.println("Time taken for op layer: " + opTime + "s");
        this.executeQuery(2, caseName, VERBOSE, all);
        double strTime = (System.nanoTime() - time)/pow(10,9);

        System.out.println("Time taken for str layer: " + strTime + "s");
        System.out.println("Total time: " + (techTime + opTime + strTime));
        return new Result(culpritString(), techMap, opMap, strMap, abduced, getPredMap(abduced, true));
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
                    System.out.println(line);
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
        for (String c : new String[]{"apt1", "gaussattack", "stuxnetattack", "sonyhack", "wannacryattack", "us_bank_hack"}) {
            System.out.println(qe.execute(c, false));
        }
    }
}
