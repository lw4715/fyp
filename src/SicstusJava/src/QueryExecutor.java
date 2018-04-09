import se.sics.jasper.*;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.*;

import static java.lang.Math.pow;

@SuppressWarnings("ALL")
public class QueryExecutor {
    // TODO: update to relative filepath of prolog files
    private static String FILEPATH = "";
    private static final String TECH = FILEPATH + "tech_rules.pl";
    private static final String OP = FILEPATH + "op_rules.pl";
    private static final String STR = FILEPATH + "str_rules.pl";

    private SICStus sp;
    private Map<String, Integer> techMap;
    private Map<String, Integer> opMap;
    private Map<String, Integer> strMap;
    private Map<String, Integer> culprits;
    private Set<String> abduced;

    QueryExecutor() {
        techMap = new HashMap<>();
        opMap = new HashMap<>();
        strMap = new HashMap<>();
        culprits = new HashMap<>();
        abduced = new HashSet<>();
        try {
            sp = new SICStus(new String[] {"redefine_warnings","off"},null);
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
            sb.append(String.format("%s [%d]", c, culprits.get(c)));
        }
        return sb.toString();
    }

    /*
    (mode)
    0 : tech
    1 : op
    2 : str
    */
    void executeQuery(int mode, String caseName, boolean verbose) {
//        SICStus sp;
        SPPredicate pred;
        SPTerm attack, culprit, r;
        SPQuery query;
        Map<String, Integer> accMap;
        String label;
        int res;
        int numDeltas;

        try
        {
            SPCanonicalAtom TIMEOUT = new SPCanonicalAtom(sp, "time_out");
            r = new SPTerm(sp, "success");
            SPTerm[] ds;

            switch(mode) {
                case 0:
                    numDeltas = 5;
                    System.out.println("TECHNICAL");
                    label = "t";
                    accMap = techMap;
                    sp.load(TECH);
                    pred = new SPPredicate(sp, "goal", numDeltas + 2, "");
                    attack = new SPTerm(sp, caseName);
                    culprit = new SPTerm(sp).putVariable();
                    ds = new SPTerm[numDeltas];
                    for (int i = 0; i < numDeltas; i++) {
                        ds[i] = new SPTerm(sp).putVariable();
                    }
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, ds[0], ds[1], ds[2], ds[3], ds[4] });
                    break;
                case 1:
                    numDeltas = 3;
                    System.out.println("OPERATIONAL");
                    label = "op";
                    accMap = opMap;
                    sp.load(OP);
                    pred = new SPPredicate(sp, "goal", numDeltas + 2, "");
                    attack = new SPTerm(sp, caseName);
                    culprit = new SPTerm(sp).putVariable();
                    ds = new SPTerm[numDeltas];
                    for (int i = 0; i < numDeltas; i++) {
                        ds[i] = new SPTerm(sp).putVariable();
                    }
                    query = sp.openQuery(pred, new SPTerm[] { attack, culprit, ds[0], ds[1], ds[2] });
                    break;
                case 2:
                    System.out.println("STRATEGIC");
                    label = "str";
                    accMap = strMap;
                    sp.load(STR);
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

            while (query.nextSolution() && count < 50) {
                if (TIMEOUT.toString().equals(r.toString())) {
                    System.out.println("TIMEOUT");
                    continue;
                }
                count++;
                for (int i = 0; i < ds.length; i++) {
                    SPTerm d = ds[i];
                    if (verbose) System.out.println(d);

                    if (d.isList()) {
                        SPTerm[] dArray = d.toTermArray();
                        res = 0;
                        for (SPTerm delta : dArray) {
                            // FIXME: recursive evidences make very large res values
                            res += getScoreAndProcess(delta, mode);
                        }
                        String ruleName = String.format("%s_%s%d", label, attack, i+1);
                        if (accMap.get(ruleName) == null || res > accMap.get(ruleName)) {
                            accMap.put(ruleName, res);
                        }
                        if (mode == 2 && caseName.equals(attack.toString())) {
                            culprits.put(culprit.toString(), res);
                            System.out.println(culprits);
                        }
                    }
                }
//                if (mode == 2) culprits.put(culprit.toString(), res);
            }

            System.out.println("Finished");
            return;
        } catch ( Exception e ) {
            e.printStackTrace();
            return;
        }
    }

    private int getScoreAndProcess(SPTerm delta, int mode) {
        int acc = 0;
        String deltaString = delta.toString();
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
            } else if (delta.toString().contains("ass(")) {
                abduced.add(delta.toString());
            }
        }
        if (deltaString.contains("case")) {
            acc += 2;
        } else if (deltaString.contains("bg")) {
            acc += 1;
        }
        return acc;
    }

    public Result execute(String caseName) {
        culprits = new HashMap<>();
        boolean verbose = false;

        double time = System.nanoTime();
        System.out.println("Start time: " + time);
        this.executeQuery(0, caseName, verbose);
        double techTime = (System.nanoTime() - time)/pow(10,9);
        time = System.nanoTime();
        System.out.println("Time taken for tech layer: " + techTime + "s");
        this.executeQuery(1, caseName, verbose);
        double opTime = (System.nanoTime() - time)/pow(10,9);
        time = System.nanoTime();
        System.out.println("Time taken for op layer: " + opTime + "s");
        time = System.currentTimeMillis();
        this.executeQuery(2, caseName, verbose);
        double strTime = (System.nanoTime() - time)/pow(10,9);
        System.out.println("Time taken for str layer: " + strTime + "s");
        System.out.println("Total time: " + (techTime + opTime + strTime));
        return new Result(culpritString(), techMap, opMap, strMap, abduced, getAbduciblesMap());
    }

    private Map<String, List<String>> getAbduciblesMap() {
        Map<String, List<String>> map = new HashMap<>();
        for (String pred : this.abduced) {
            String key = pred.substring(4, pred.length() - 1).split("\\(")[0];
            List<String> val = new ArrayList<>();
            val.addAll(scanFileForPredicate(TECH, key));
            val.addAll(scanFileForPredicate(OP, key));
            val.addAll(scanFileForPredicate(STR, key));
            map.put(key, val);
        }
        return map;
    }

    private List<String> scanFileForPredicate(String filename, String pred) {
        List<String> r = new ArrayList<>();
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            br.lines().forEach(line -> {
                if (line.contains(pred) && line.contains("rule(") && !line.contains("abducible(") && !line.contains("%")) {
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
        //{"us_bank_hack", "apt1", "gaussattack", "stuxnetattack", "sonyhack", "wannacryattack"};
        QueryExecutor qe = new QueryExecutor();
        System.out.println(qe.execute("gaussattack"));
        System.out.println(qe.abduced);
//        System.out.println(qe.execute("wannacryattack"));

    }

}
